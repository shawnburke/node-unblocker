var url = require('url')
	,http = require('http')
	,https = require('https')
	,zlib = require('zlib');

var config = require('../config')
	,cookies = require('./cookies')
	,utils = require('./utils')
	,blocklist = require('./blocklist');

	var util = require('util');


var portmap 		= {"http:":80,"https:":443},
	re_abs_url 	= /("|'|=)(http)/ig, // "http, 'http, or =http (no :// so that it matches http & https)
	re_abs_no_proto 	= /("|'|=)(\/\/)/ig, // matches //site.com style urls where the protocol is auto-sensed
	re_rel_root = /((href|src)=['"]{0,1})(\/\w)/ig, // matches src="/asdf/asdf"
	// no need to match href="asdf/adf" relative links - those will work without modification
	
	
	re_css_abs = /(url\(\s*)(http)/ig, // matches url( http
	re_css_rel_root = /(url\(\s*['"]{0,1})(\/\w)/ig, // matches url( /asdf/img.jpg
	
	// partial's dont cause anything to get changed, they just cause the packet to be buffered and rechecked
	re_html_partial = /("|'|=|\(\s*)[ht]{1,3}$/ig, // ', ", or = followed by one to three h's and t's at the end of the line
	re_css_partial = /(url\(\s*)[ht]{1,3}$/ig; // above, but for url( htt

// charset aliases which charset supported by native node.js
var charset_aliases = {
	'ascii':           'ascii',
	'us':              'ascii',
	'us-ascii':        'ascii',
	'utf8':            'utf8',
	'utf-8':           'utf8',
	'ucs-2':           'ucs2',
	'ucs2':            'ucs2',
	'csunicode':       'ucs2',
	'iso-10646-ucs-2': 'ucs2'
};

// charset aliases which iconv doesn't support
// this is popular jp-charset only, I think there are more...
var charset_aliases_iconv = {
	'windows-31j':  'cp932',
	'cswindows31j': 'cp932',
	'ms932':        'cp932'
};

/**
* Makes the outgoing request and relays it to the client, modifying it along the way if necessary
*
* todo: get better at fixing / urls
* todo: fix urls that start with //
*/
function proxy(request, response) {


	var uri = url.parse(this.getRealUrl(request.url));
	// make sure the url in't blocked
	if(!blocklist.urlAllowed(uri)){
      return redirectTo(request, response, "?error=Please use a different proxy to access this site");
    }

	// redirect urls like /proxy/http://asdf.com to /proxy/http://asdf.com/ to make relative image paths work
	if (uri.pathname == "/" && request.url.substr(-1) != "/") {
		return redirectTo(request, response, request.url + "/");
	}
	
	uri.port = uri.port || portmap[uri.protocol];
	uri.pathname = uri.search ? uri.pathname + uri.search : uri.pathname;
	
	
	headers = copy(request.headers);
	
	delete headers.host;
	
	// todo: grab any new cookies in headers.cookie (set by JS) and store them in the session
	// (assume / path and same domain as request's referer)
	headers.cookie = this.getCookies(request, uri);
	
	console.log("sending these cookies: " + headers.cookie);
	
	// overwrite the referer with the correct referer
	if(request.headers.referer){
		headers.referer = this.getRealUrl(request.headers.referer);
	}
	
	var options = {
		host: uri.host,
		port: uri.port,
		path: uri.pathname,
		method: request.method,
		headers: headers
	}
	
	// what protocol to use for outgoing connections.
	var proto = (uri.protocol == 'https:') ? https : http;
	var self = this;

	
	var remote_request = proto.request(options, function(remote_response){
	
		// make a copy of the headers to fiddle with
		var headers = copy(remote_response.headers);
		
		var content_type = headers['content-type'] || "unknown",
			ct = content_type.split(";")[0];
		
		var needs_parsed = ([
			'text/html', 
			'application/xml+xhtml', 
			'application/xhtml+xml',
			'text/css', 
			'text/javascript', 
			'application/javascript',
			'application/x-javascript'
		].indexOf(ct) != -1);
		
		// if we might be modifying the response, nuke any content-length headers
		if(needs_parsed){
			delete headers['content-length'];
		}
		
		// detect charset from content-type headers
		var charset = content_type.match(/\bcharset=([\w\-]+)\b/i);
		charset = charset ? normalizeIconvCharset(charset[1].toLowerCase()) : undefined;

		var needs_decoded = (needs_parsed && headers['content-encoding'] == 'gzip');
		
		// we're going to de-gzip it, so nuke that header
		if(needs_decoded){
			delete headers['content-encoding'];
		}
		
		// fix absolute path redirects 
		// (relative redirects will be 302'd to the correct path, and they're disallowed by the RFC anyways
		// todo: also fix refresh and url headers
		if(headers.location && headers.location.substr(0,4) == 'http'){
			headers.location = self.thisSite(request) + "/" + headers.location;
			console.log("fixing redirect");
		}
		
		if(headers['set-cookie']){
			self.storeCookies(request, uri, headers['set-cookie']);
			delete headers['set-cookie'];
		}
		
		//  fire off out (possibly modified) headers
		response.writeHead(remote_response.statusCode, headers);
		
		//console.log("content-type: " + ct);
		//console.log("needs_parsed: " + needs_parsed);
		//console.log("needs_decoded: " + needs_decoded);
		
		
		// sometimes a chunk will end in data that may need to be modified, but it is impossible to tell
		// in that case, buffer the end and prepend it to the next chunk
		var chunk_remainder;
		
		// if charset is utf8, chunk may be cut in the middle of 3byte character,
		// we need to buffer the cut data and prepend it to the next chunk
		var chunk_remainder_bin;
		
		// todo : account for varying encodings
		function parse(chunk){
			//console.log("data event", request.url, chunk.toString());
			
			if( chunk_remainder_bin ){
				var buf = new Buffer(chunk_remainder_bin.length + chunk.length);
				chunk_remainder_bin.copy(buf);
				chunk.copy(buf, chunk_remainder_bin.length);
				chunk_remainder_bin = undefined;
				chunk = buf;
			}
			if( charset_aliases[charset] === 'utf8' ){
				var cut_size = utf8_cutDataSizeOfTail(chunk);
				//console.log('cut_size = ' + cut_size);
				if( cut_size > 0 ){
					chunk_remainder_bin = new Buffer(cut_size);
					chunk.copy(chunk_remainder_bin, 0, chunk.length - cut_size);
					chunk = chunk.slice(0, chunk.length - cut_size);
				}
			}
			
			// stringily our chunk and grab the previous chunk (if any)
			chunk = decodeChunk(chunk);
			
			if(chunk_remainder){
				chunk = chunk_remainder + chunk;
				chunk_remainder = undefined;
			}
			
			var thisSite = self.thisSite(request);

			// first replace any complete urls
			chunk = chunk.replace(re_abs_url, "$1" + thisSite + "/$2");
			chunk = chunk.replace(re_abs_no_proto, "$1" + thisSite + "/" + uri.protocol + "$2");
			// next replace urls that are relative to the root of the domain
			chunk = chunk.replace(re_rel_root, "$1" + thisSite + "/" + uri.protocol + "//" + uri.hostname + "$3");
			
			// if we're in a stylesheet, run a couple of extra regexs to avoid 302's
			if(ct == 'text/css'){
				console.log('running css rules');
				chunk = chunk.replace(re_css_abs, "$1" + thisSite + "/$2");
				chunk = chunk.replace(re_css_rel_root, "$1" + thisSite + "/" + uri.protocol + "//" + uri.hostname + "$2");			
			}
			
			// second, check if any urls are partially present in the end of the chunk,
			// and buffer the end of the chunk if so; otherwise pass it along
			if(chunk.match(re_html_partial)){
				chunk_remainder = chunk.substr(-4); // 4 characters is enough for "http, the longest string we should need to buffer
				chunk = chunk.substr(0, chunk.length -4);
			}
			
			chunk = chunk.replace('</head>', '<meta name="ROBOTS" content="NOINDEX, NOFOLLOW">\r\n</head>');
			
			chunk = self.filterHtml(chunk);
			
			response.write(encodeChunk(chunk));
		}

		// Iconv instance for decode and encode
		var decodeIconv, encodeIconv;

		// decode chunk binary to string using charset
		function decodeChunk(chunk){
			// if charset is undefined, detect from meta headers
			if( !charset ){
				var re = chunk.toString().match(/<meta\b[^>]*charset=([\w\-]+)/i);
				// if we can't detect charset, use utf-8 as default
				// CAUTION: this will become a bug if charset meta headers are not contained in the first chunk, but probability is low
				charset = re ? normalizeIconvCharset(re[1].toLowerCase()) : 'utf-8';
			}
			//console.log("charset: " + charset);

			if( charset in charset_aliases ){
				return chunk.toString(charset_aliases[charset]);
			} else {
				if( !decodeIconv ) decodeIconv = new Iconv(charset, 'UTF-8//TRANSLIT//IGNORE');
				return decodeIconv.convert(chunk).toString();
			}
		}

		// normalize charset which iconv doesn't support
		function normalizeIconvCharset(charset){
			return charset in charset_aliases_iconv ? charset_aliases_iconv[charset] : charset;
		}

		// encode chunk string to binary using charset
		function encodeChunk(chunk){
			if( charset in charset_aliases ){
				return new Buffer(chunk, charset_aliases[charset]);
			} else {
				if( !encodeIconv ) encodeIconv = new Iconv('UTF-8', charset + '//TRANSLIT//IGNORE');
				return encodeIconv.convert(chunk);
			}
		}

		// check tail of the utf8 binary and return the size of cut data
		// if the data is invalid, return 0
		function utf8_cutDataSizeOfTail(bin){
			var len = bin.length;
			if( len < 4 ) return 0; // don't think about the data of less than 4byte

			// count bytes from tail to last character boundary
			var skipped = 0;
			for( var i=len; i>len-4; i-- ){
				var b = bin[i-1];
				if( (b & 0x7f) === b ){ // 0xxxxxxx (1byte character boundary)
					if( i === len ){
						return 0;
					} else {
						break; // invalid data
					}
				} else if( (b & 0xbf) === b ){ //10xxxxxx (is not a character boundary)
					skipped++;
				} else if( (b & 0xdf) === b ){ //110xxxxx (2byte character boundary)
					if( skipped === 0 ){
						return 1;
					} else if( skipped === 1 ){
						return 0;
					} else {
						break; // invalid data
					}
				} else if( (b & 0xef) === b ){ //1110xxxx (3byte character boundary)
					if( skipped <= 1 ){
						return 1 + skipped;
					} else if( skipped === 2 ){
						return 0;
					} else {
						break; // invalid data
					}
				} else if( (b & 0xf7) === b ){ //11110xxx (4byte character boundary)
					if( skipped <= 2 ){
						return 1 + skipped;
					} else if( skipped === 3 ) {
						return 0;
					} else {
						break; // invalid data
					}
				}
			}
			// invalid data, return 0
			return 0;
		}

		// if we're dealing with gzipped input, set up a stream decompressor to handle output
		if(needs_decoded) {
			remote_response = remote_response.pipe(zlib.createUnzip());
		}

		// set up a listener for when we get data from the remote server - parse/decode as necessary
		remote_response.addListener('data', function(chunk){
			if(needs_parsed) {
				parse(chunk);		
			} else {
				response.write(chunk);
			}
		});

		// clean up the connection and send out any orphaned chunk
		remote_response.addListener('end', function() {
			// if we buffered a bit of text but we're now at the end of the data, then apparently
			// it wasn't a url - send it along
			if(chunk_remainder){
				response.write(chunk_remainder);
				chunk_remainder = undefined;
			}
			response.end();
		});
		

		
	});
	
	remote_request.addListener('error', function(err){
		self.onRequestError(err, request, response);
	});
	
	// pass along POST data
	request.addListener('data', function(chunk){
		remote_request.write(chunk);
	});
	
	// let the remote server know when we're done sending data
	request.addListener('end', function(){
		remote_request.end();
	});
}

/**
* returns a shallow copy of an object
*/
function copy(source){
	var n = {};
	for(var key in source){
		if(source.hasOwnProperty(key)){
			n[key] = source[key];
		}
	}
	return n;
}

function Proxy(options){
	
	if (!options) {
		throw new Error("options required");
	}

	if (!options.thisSite) {
		throw new Error ("options.thisSite required");
	}
 
	this.handler = proxy.bind(this);

	function getRealUrl(path){
		return path;
	}
	
	this.getRealUrl = options.getRealUrl || getRealUrl;
	this.thisHost = options.thisHost || function(req){return req.headers.host;};
	this.thisSite = options.thisSite;
	this.getCookies = options.getCookies || function(){return {}};
	this.storeCookies = options.storeCookies || function(){};
	this.onRequestError = options.onRequestError || function(){};
	this.filterHtml = options.filterHtml || function(html) {return html;};

}

module.exports = Proxy;

