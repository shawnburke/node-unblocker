/***************
* node-unblocker: Web Proxy for evading firewalls and content filters, 
* similar to CGIProxy or PHProxy
*
*
* This project is hosted on github:  https://github.com/nfriedly/node-unblocker
*
* By Nathan Friedly - http://nfriedly.com 
* Released under the terms of the GPL v3
*/

/*
todo:
 - stress test (apache bench?)
 - add error handeling
 - look into npm
 - mini-form, no cookies,  and no script options
 - figure out why the google png has extra data at the beginning and end
 - clean things up a bit
 - turn simple-session into a standalone library
*/

// native imports
var http = require('http'),
	https = require('https'),
	url = require('url'),
	querystring = require('querystring'),
	path = require("path"),
	fs = require("fs"),
	zlib = require('zlib'),
	cluster = require('cluster'),
	Iconv = require('iconv').Iconv,
	numCPUs = require('os').cpus().length;


// local dependencies
var blocklist = require('./lib/blocklist');
  
// the configuration file
var config = require('./config');

// third-party dependencies
var connect = require('connect'); // todo: call by version once 2.x is listed in npm

/*
var RedisStore = require('connect-redis')(connect),
	redis;
// the redis client differs depending on if you're using redistogo (heroku) or not
if(config.redistogo_url) {
	redis = require('redis-url').connect(config.redistogo_url);
} else {
	redis = require('redis').createClient(config.redis_port, config.redis_host, config.redis_options);
}

*/	


var Proxy = require('./lib/proxy');




/**
* Takes a /proxy/http://site.com url from a request or a referer and returns the http://site.com/ part
*/
function getRealUrl(path){
		var uri = url.parse(path),
		real_url = uri.pathname.substr(7); // "/proxy/" is 7 characters long.
		// we also need to include any querystring data in the real_url
		return uri.search ? real_url + uri.search : real_url;
}

// returns the configured host if one exists, otherwise the host that the current request came in on
function thisHost(request){
	return (config.host) ? config.host : request.headers.host;
}

// returns the http://site.com/proxy
function thisSite(request){
	return 'http://' + thisHost(request) + '/proxy';
}

function onRequestError(err, request, response) {
	redirectTo(request, response, "?error=" + err.toString());
}

var proxy = new Proxy({
	getRealUrl: getRealUrl,
	thisHost: thisHost,
	thisSite: thisSite,
	getCookies: getCookies,
	storeCookies:storeCookies,
	filterHtml: add_ga
});

var server = connect()
	.use(connect.cookieParser(config.secret))
  	.use(connect.session({
  		//store: new RedisStore({client: redis}),
  		cookie: { path: '/', httpOnly: false, maxAge: null }
  	}))
	.use(function(request, response){
	var url_data = url.parse(request.url);
	
	console.log("(" + process.pid + ") New Request: ", request.url);
	
	
    incrementRequests();
	request.on('end', decrementRequests);
	
	// if the user requested the "home" page
	// (located at /proxy so that we can more easily tell the difference 
	// between a user who is looking for the home page and a "/" link)
	if(url_data.pathname == "/proxy"){
		request.url = "/index.html"; 
		// todo: refactor this to make more sense
		return sendIndex(request, response);
	}
	
	// this is for users who's form actually submitted due to JS being disabled
	if(url_data.pathname == "/proxy/no-js"){
		// grab the "url" parameter from the querystring
		var site = querystring.parse( url.parse(request.url).query ).url;
		// and redirect the user to /proxy/url
		redirectTo(request, response, site || "");
	}
	
	// only requests that start with this get proxied - the rest get 
	// redirected to either a url that matches this or the home page
	if(url_data.pathname.indexOf("/proxy/http") == 0){
		return proxy.handler(request, response);
	}
	
	// the status page
	if(url_data.pathname == "/proxy/status"){
		return status(request, response);
	}
	
	// disallow almost everything via robots.txt
	if(url_data.pathname == "robots.txt"){
		response.writeHead("200", {"Content-Type": "text/plain"});
		response.write("User-agent: *\n" + 
			"Disallow: /proxy/http\n" +
			"Disallow: /proxy/http:\n" + 
			"Disallow: /proxy/http:/\n\n" + 
			"Disallow: /proxy/https\n" +
			"Disallow: /proxy/https:\n" + 
			"Disallow: /proxy/https:/\n\n"
		);
		response.end(); 
	}
	
	// any other url gets redirected to the correct proxied url if we can
	// determine it based on their referrer, or the home page otherwise
	return handleUnknown(request, response);

}); // we'll start the server at the bottom of the file



/**
* Checks the user's session and the requesting host and adds any cookies that the requesting 
* host has previously set.
*
* Honors domain, path, and expires directives. 
*
* Does not currently honor http / https only directives.
*/
function getCookies(request, uri){
  if( uri.hostname ) {
    var hostname_parts = uri.hostname.split(".");
  }
	var cookies = "",
		i = (hostname_parts[hostname_parts.length-2] == "co") ? 3 : 2, // ignore domains like co.uk
		cur_domain,
		path_parts = uri.pathname.split("/"),	
		cookies = {}, // key-value store of cookies.
		output = [], // array of cookie strings to be joined later
		session = request.session;
		
	// We start at the least specific domain/path and loop towards most specific so that a more 
	// overwrite specific cookie will a less specific one of the same name.
	// forst we loop through all possible sub domains that start with a dot,
	// then the current domain preceded by a dot
	for(; i<= hostname_parts.length; i++){
		cur_domain = "." + hostname_parts.slice(-1*i).join('.'); // first .site.com, then .www.site.com, etc.
		readCookiesForDomain(cur_domain);
	}
	
	// now, finally, we check for cookies that were set on the exact current domain without the dot
	readCookiesForDomain(uri.hostname);
	
	function readCookiesForDomain(cur_domain){
		
		if(!session[cur_domain]) return;
		
		var j, cur_path;
		
		for(j=1; j < path_parts.length; j++){
		
			cur_path = path_parts.slice(0,j).join("/");
			if(cur_path == "") cur_path = "/";
			
			if(session[cur_domain][cur_path]){
				for(var cookie_name in session[cur_domain][cur_path]){
					
					// check the expiration date - delete old cookies
					if(isExpired(session[cur_domain][cur_path][cookie_name])){
						delete session[cur_domain][cur_path][cookie.name];
					} else {
						cookies[cookie_name] = session[cur_domain][cur_path][cookie_name].value;
					}
				}
			}
		}
	}
	
	// convert cookies from key/value pairs to single strings for each cookie
	for(var name in cookies){
		output.push(name + "=" + cookies[name]);
	};
	
	// join the cookie strings and return the final output
	return output.join("; ");
}

/**
* Parses the set-cookie header from the remote server and stores the cookies in the user's session
*/
function storeCookies(request, uri, cookies){
	console.log('storing these cookies: ', cookies);

	if(!cookies) return;
	
	var parts, name_part, thisCookie, domain;
	
	cookies.forEach(function(cookie){
		domain = uri.hostname;
		parts = cookie.split(';');
		name_part = parts.shift().split("=");
		thisCookie = {
			name: name_part.shift(), // grab everything before the first =
			value: name_part.join("=") // everything after the first =, joined by a "=" if there was more than one part
		}
		parts.forEach(function(part){
			part = part.split("=");
			thisCookie[part.shift().trimLeft()] = part.join("=");
		});
		if(!thisCookie.path){
			thisCookie.path = uri.pathname;
		}
		// todo: enforce domain restrictions here so that servers can't set cookies for ".com"
		domain = thisCookie.domain || domain;
		
		request.session[domain] = request.session[domain] || {};
		
		// store it in the session object - make sure the namespace exists first
		request.session[domain][thisCookie.path] = request.session[domain][thisCookie.path] || {};
		request.session[domain][thisCookie.path][thisCookie.name] = thisCookie;

		// now that the cookie is set (deleting any older cookie of the same name), 
		// check the expiration date and delete it if it is outdated
		if(isExpired(thisCookie)){
			console.log('deleting cookie', thisCookie.expires);
			delete request.session[domain][thisCookie.path][thisCookie.name];
		}

	});
}

/**
* Accepts a cookie object and returns true if it is expired
* (technically all cookies expire at the end of the session because we don't persist them on
*  the client side, but some cookies need to expire sooner than that.)
*/
function isExpired(cookie){
	if(cookie.expires){
		var now = new Date(),
			expires = new Date(cookie.expires);
		return (now.getTime() >= expires.getTime());
	}
	return false; // no date set, therefore it expires at the end of the session 
}

/**
* This is what makes this server magic: if we get an unrecognized request that wasn't corrected by
* proxy's filter, this checks the referrer to determine what the path should be, and then issues a
* 302 redirect to a proxied url at that path
*
* todo: handle querystring and post data
*/
function handleUnknown(request, response){

	if(request.url.indexOf('/proxy/') == 0){
		// no trailing slashes
		if(request.url == "/proxy/"){
			return redirectTo(request, response, "");
		}
		
		// we already know it doesn't start with http, so lets fix that first
		return redirectTo(request, response, 
			"/http://" + request.url.substr(7) // "/proxy/".length = 7
		);
	}
	
	// if there is no referer, then either they just got here or we can't help them
	if(!request.headers.referer){
		return redirectTo(request, response, ""); // "" because we don't want a trailing slash
	}
	
	var ref = url.parse(request.headers.referer);
	
	// if we couldn't parse the referrer or they came from another site, they send them to the home page
	if(!ref || ref.host != thisHost(request)){
		return redirectTo(request, response, ""); // "" because we don't want a trailing slash
	}
	
	// now we know where they came from, so we can do something for them
	if(ref.pathname.indexOf('/proxy/http') == 0){
		var real_url = url.parse(getRealUrl(ref.pathname));
		
		// now, take the requested pat on the previous known host and send the user on their way
		return redirectTo(request, response, real_url.protocol +"//"+ real_url.host + request.url);
	}
	
	// else they were refered by something on this site that wasn't the home page and didn't come 
	// through the proxy - aka this shouldn't happen
	redirectTo(request, response, "");
}



function redirectTo(request, response, site){
	site = site || "";
	if(site.length && site.substr(0,1) != "/" && site.substr(0,1) != "?"){
		site = "/" + site;
	}
	if(site.substr(0, 6) == "/proxy") { // no /proxy/proxy redirects
		site = site.substr(6);
	}
	if(site == "/") site = ""; // no endless redirect loops
	try {
		response.writeHead('302', {'Location': thisSite(request) + site});
		console.log("recirecting to " + thisSite(request) + site);
	} catch(ex) {
		// the headers were already sent - we can't redirect them
		console.error("Failed to send redirect", ex);
	}
	response.end();
}


var ga = "";
function add_ga(html) {
	if(config.google_analytics_id) {
		ga = ga || [
		  "<script type=\"text/javascript\">"
		  ,"var _gaq = []; // overwrite the existing one, if any"
		  ,"_gaq.push(['_setAccount', '" + config.google_analytics_id + "']);"
		  ,"_gaq.push(['_trackPageview']);"
		  ,"(function() {"
		  ,"  var ga = document.createElement('script'); ga.type = 'text/javascript'; ga.async = true;"
		  ,"  ga.src = ('https:' == document.location.protocol ? 'https://ssl' : 'http://www') + '.google-analytics.com/ga.js';"
		  ,"  var s = document.getElementsByTagName('script')[0]; s.parentNode.insertBefore(ga, s);"
		  ,"})();"
		  ,"</script>"
		].join("\n");

		html = html.replace("</body>", ga + "\n\n</body>");	
	}
	return html;
}


/**
 * placeholder for compressed & uncompressed versions of index.html
 */
var index = {};

/**
 * Reads the index.html file into memory and compresses it so that it can be more quickly served
 */
function setupIndex(){
	var raw_index = fs.readFileSync(path.join(__dirname,'index.html')).toString();
	var package_info = JSON.parse(fs.readFileSync(path.join(__dirname,'package.json')));
	raw_index = raw_index.replace('{version}', package_info.version)
	raw_index = add_ga(raw_index);
	index.raw = raw_index;
	zlib.deflate(raw_index, function(data){index.deflate = data;});
	zlib.gzip(raw_index,  function(data){index.gzip = data;})
}

/**
 * Sends out the index.html, using compression if the client supports it
 */
function sendIndex(request, response, google_analytics_id){
	var headers = {"content-type": "text/html"};
	
	var acceptEncoding = request.headers['accept-encoding'];
	if (!acceptEncoding) {
		acceptEncoding = '';
	}
	
	var data;
	
	// check that the compressed version exists in case we get a request 
	// that comes in before the compression finishes (serve those raw)
	if (acceptEncoding.match(/\bdeflate\b/) && index.deflate) {
		headers['content-encoding'] = 'deflate';
		data = index.deflate
	} else if (acceptEncoding.match(/\bgzip\b/) && index.gzip) {
		headers['content-encoding'] = 'gzip';
		data = index.gzip;
	} else {
		data = index.raw;
	}

	response.writeHead(200, headers);
	response.end(data);
}



function incrementRequests(){
	process.send({type: "request.start"});
}

function decrementRequests(){
	process.send({type: "request.end"});
}

var waitingStatusResponses = [];

// simple way to get the curent status of the server
function status(request, response){
	console.log("status request recieved on pid " + process.pid);
	response.writeHead("200", {"Content-Type": "text/plain", "Expires": 0});
	
	// only send out a new status request if we don't already have one in the pipe
	if(waitingStatusResponses.length == 0) {
		console.log("sending status request message");
		process.send({type: "status.request", from: process.pid});
	}
	
	// 1 second timeout in case the master doesn't respond quickly enough
	response.timeout = setTimeout(function(){
		console.log("Error: status responses timeout reached");
		sendStatus({error: "No response from the cluster master after 1 second"});
	}, 1000);
	
	waitingStatusResponses.push(response);
}

function sendStatus(status){
	var big_break	= "====================";
	var small_break	= "--------------------";
	var lines = [
		"Server Status",
		big_break,
		(new Date()).toString(),
		"",
		"Cluster Status",
		small_break
	];
	
	for(key in status) {
		if(status.hasOwnProperty(key)) {
			if(key == "type" || key == "to") {
				continue;
			}
			var val = status[key];
			lines.push(key + ": " + val);
		}
	}
	
	var body = lines.join("\n");
	
	waitingStatusResponses.forEach(function (response) {
		response.end(body);
		clearTimeout(response.timeout);
	});
	
	waitingStatusResponses.length = 0;
};

/**
 * Set up clustering
 */
if (cluster.isMaster) {

	// the master will track a few statics and keep the workers up and running
	
	
	var child_count = 0,
		startTime = new Date(),
		total_requests = 0,
		total_open_requests = 0,
		max_open_requests = 0;
		
	var MINUTE = 60,
		HOUR = 60 * 60,
		DAY = HOUR * 24;
		
	function prettyTime(date) {
		var diff = ((new Date()).getTime() - date.getTime())/1000;
		if (diff > DAY) {
			return Math.floor(diff/DAY) + " days";
		} else if (diff > HOUR) {
			return Math.floor(diff/HOUR) + " hours";
		} else if (diff > MINUTE) {
			return Math.floor(diff/MINUTE) + " minutes";
		} else {
			return Math.round(diff*10)/10 + " seconds";
		}
	}
	
	function workersExcept(pid) {
		return workers.filter( function(w) {
			return w.pid != pid;
		});
	}
	
	var workers = [];
	
	function createWorker() {
		var worker = cluster.fork();
		child_count++;
		workers.push(worker);
		
		worker.open_requests = 0;
		worker.start_time = new Date();
		
		worker.on('message', function (message) {
			// if there's no type, then we don't care about it here
			if(!message.type) {
				return;
			}
			
			console.log('message recieved by master ', message);
			
			// if it's a status request sent to everyone, respond with the master's status before passing it along
			if (message.type == "status.request") {
				var data = {
					type: "status.response",
					"Master PID": process.pid, 
					"Online Since": startTime.toString() + "(about " + prettyTime(startTime) + ")", 
					"Workers Started": child_count, 
					"Total Requests Served": total_requests,
					"Current Open Requests": total_open_requests,
					"Max Open Requests": max_open_requests
				};
				
				var uptime = ((new Date).getTime() - startTime.getTime())/1000;
				if (total_requests > uptime) {
					data["Requests Per Second (average)"] = total_requests / uptime;
				} else if (total_requests > uptime/MINUTE) {
					data["Requests Per Minute (average)"] = total_requests / (uptime/MINUTE);
				} else if (total_requests > uptime/HOUR) {
					data["Requests Per Hour (average)"] = total_requests / (uptime/HOUR);
				} else {
					data["Requests Per Day (average)"] = total_requests / (uptime/DAY);
				}
				
				data.Workers = "";
				workers.forEach(function(w) {
					data.Workers += "\n - " + w.pid + " online for " + prettyTime(w.start_time);
				});
				
				worker.send(data);
			}
			
			if (message.type == "request.start") {
				worker.open_requests++;
				total_open_requests++;
				if (max_open_requests < total_open_requests) {
					max_open_requests = total_open_requests;
				}
				total_requests++;
			}
			
			if (message.type == "request.end") {
				worker.open_requests--;
				total_open_requests--;
			}
		});
	}

	// if we're in the master process, create one worker for each cpu core
	for (var i = 0; i < numCPUs; i++) {
		createWorker();
	}
	
	// when the worker dies, note the exit code, remove it from the workers array, and create a new one 
	cluster.on('exit', function(worker) {
		total_open_requests = total_open_requests - worker.open_requests;
		workers = workersExcept(worker.pid)
		createWorker();
	});

} else {
	// if we're a worker, read the index file and then fire up the server
	setupIndex();
	http.Server(server).listen(config.port, config.ip);
	console.log('node-unblocker proxy server with pid ' + process.pid + ' running on ' + 
		((config.ip) ? config.ip + ":" : "port ") + config.port
	);
	
	process.on('message', function (message) {
		if (!message.type) {
			return;
		}
		console.log("messge recieved by child (" + process.pid + ") ", message);
		if (message.type == "status.response") {
			sendStatus(message);
		}
	});
}

