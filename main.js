/*
 * This is a sysops command agent. This is a 2 part project.
 * This agent runs in the targeted computer in daemon mode, and waits
 * for the control server to execute command. It uses encryption commands
 * to keep the data transfer safe.
 * 
 * It should not be run in adminstrative mode or root mode.
 * 
 * Currently this can handle native commands only.
 * Todo : Execute js codes using sandbox as well.
 * 
 * 
 * @author Bismay K Mohapatra bismay4u@gmail.com
 * @version 3.0
 * */
var crypto = require('crypto');
var cluster = require('cluster');
var os = require("os");

var masterIP = "0.0.0.0";
var hostPort = 8090;

var algorithm = 'aes-128-cbc';
var password = "qwertyuiopqwieuu";
var iv = "0123456789123456";
var enableEncrypt = false;
var DEBUG = false;

var CMD_SET = {
	"ps": "ps -aux;"
};
var CMD_NOTALLOWED = ["sudo", "top"];

var OS_TYPE = os.type().toUpperCase();

function Server() {
	var cmdServer = this;
	var password = null;
	var enableEncrypt = false;

	this.start = function (host, port, pwd, enableCrypt) {
		this.password = pwd;
		this.enableEncrypt = enableCrypt;

		if (host == null || port == null) {
			console.error("HOST/PORT Not Defined");
			process.exit();
		}

		/*
		 * Dependencies
		 */
		var http = require('http'),
			url = require('url'),
			exec = require('child_process').exec;

		/*
		 * Server Config
		 */
		var thisServerUrl = "http://" + host + ":" + port;

		/*
		 * Main
		 */
		http.createServer(function (req, res) {
			req.setTimeout(240000);
			req.addListener('end', function () {

			});
			//console.log(cmdServer.decrypt(req.url.substr(2)));
			//var parsedUrl = url.parse(cmdServer.decrypt(req.url.substr(2)), true);
			var parsedUrl = url.parse(req.url, true);
			var cmd = parsedUrl.query['cmd'];
			var path = parsedUrl.query['path'];
			var async = parsedUrl.query['async'];

			if (path == null || path.length <= 0) {
				path = os.homedir();
			}

			if (cmd) {
				cmdOriginal = cmd;
				cmd = cmd.toLowerCase();

				cmd0 = cmd.split(" ")[0];

				if (CMD_NOTALLOWED.indexOf(cmd0) >= 0) {
					stderr = "CMD `" + cmd0 + "` is not allowed !!!";
					res.writeHead(412, {
						'Content-Type': 'text/plain'
					});
					res.end(stderr + '\n');
					return;
				}

				if (CMD_SET[cmd] != null && CMD_SET[cmd].length > 0) {
					cmd = CMD_SET[cmd];
				}

				//Special Commands
				switch (cmd) {
					case "me":
						sysData = {
							"PLATFORM": os.platform(),
							"HOST": masterIP,
							"PORT": hostPort,
						};
						res.writeHead(200, {
							'Content-Type': 'text/json'
						});
						res.end(cmdServer.encrypt(JSON.stringify(sysData)) + '\n');
						break;
					case "info":
						sysData = ["infosys", "infoprs", "infocpu", "infonet", "infouser", ];
						res.writeHead(200, {
							'Content-Type': 'text/json'
						});
						res.end(cmdServer.encrypt(JSON.stringify(sysData)) + '\n');
						return;
						break;
					case "infosys":
						sysData = {
							"PLATFORM": os.platform(),
							"RELEASE": os.release(),
							"TYPE": os.type(),
							"ARCH": os.arch(),
							"MEM_FREE": os.freemem(),
							"MEM_TOTAL": os.totalmem(),
							"LOADAVG": os.loadavg(),
							"UPTIME": os.uptime(),
							"HOST": os.hostname(),
							"DIR_HOME": os.homedir(),
							"DIR_TMP": os.tmpdir(),
						};
						res.writeHead(200, {
							'Content-Type': 'text/json'
						});
						res.end(cmdServer.encrypt(JSON.stringify(sysData)) + '\n');
						return;
						break;
					case "infoprocess":
					case "infoprs":
						sysData = {
							"MEM_FREE": os.freemem(),
							"MEM_TOTAL": os.totalmem(),
							"LOADAVG": os.loadavg(),
							"UPTIME": os.uptime(),
							"PROCESS": process.config,
						};
						res.writeHead(200, {
							'Content-Type': 'text/json'
						});
						res.end(cmdServer.encrypt(JSON.stringify(sysData)) + '\n');
						return;
						break;
					case "infocpu":
						sysData = {
							"PLATFORM": os.platform(),
							"RELEASE": os.release(),
							"TYPE": os.type(),
							"ARCH": os.arch(),
							"CPUS": os.cpus(),
						};
						res.writeHead(200, {
							'Content-Type': 'text/json'
						});
						res.end(cmdServer.encrypt(JSON.stringify(sysData)) + '\n');
						return;
						break;
					case "infonet":
						sysData = {
							"HOST": os.hostname(),
							"NETWORKINTERFACE": os.networkInterfaces(),
						};
						res.writeHead(200, {
							'Content-Type': 'text/json'
						});
						res.end(cmdServer.encrypt(JSON.stringify(sysData)) + '\n');
						return;
						break;
					case "infouser":
						sysData = {
							"USER": os.userInfo(),
							"DIR_HOME": os.homedir(),
							"DIR_TMP": os.tmpdir(),
						};
						res.writeHead(200, {
							'Content-Type': 'text/json'
						});
						res.end(cmdServer.encrypt(JSON.stringify(sysData)) + '\n');
						return;
						break;
					case "passthru":
					case "forward":
					case "bypass":
						payload = parsedUrl.query['payload'];
						if (payload == null || payload.length <= 1) {
							return res.end("Error in Payload Decoding");
						}
						payload = JSON.parse(payload);
						if (typeof payload.target == "string") {
							nextHOP = 'http://' + payload.target + '/?cmd=' + payload.cmd;
							http.get(nextHOP, function (response) {
								var data = '';

								// A chunk of data has been recieved.
								response.on('data', (chunk) => {
									data += chunk;
								});

								// The whole response has been received. Print out the result.
								response.on('end', () => {
									res.end(cmdServer.encrypt(data) + '\n');
								});
							}).on("error", (err) => {
								res.end(cmdServer.encrypt(err.message) + '\n');
							});
						} else {
							hopno = parsedUrl.query['hopno'];
							if (hopno == null) hopno = 0;

							if (hopno == payload.target.length - 1) {
								nextHOP = 'http://' + payload.target[hopno] + '/?cmd=' + payload.cmd;
							} else {
								nextHOP = 'http://' + payload.target[hopno] + '/?cmd=forward&hopno=' + (hopno + 1) + '&payload=' + JSON.stringify(payload);
							}
							http.get(nextHOP, function (response) {
								var data = '';

								// A chunk of data has been recieved.
								response.on('data', (chunk) => {
									data += chunk;
								});

								// The whole response has been received. Print out the result.
								response.on('end', () => {
									res.end(cmdServer.encrypt(data) + '\n');
								});
							}).on("error", (err) => {
								res.end(cmdServer.encrypt(err.message) + '\n');
							});
						}
						return;
						// case "test":
						// 	throw new Error('User generated fault.');
						// 	return;
						// 	break;
				}

				cmd = "cd " + path + ";" + cmdOriginal;

				if(DEBUG && (OS_TYPE == "LINUX" || OS_TYPE == "DARWIN")) {
					cmd = "cd " + path + ";echo \"At Path : `pwd`\";echo \"By User : `whoami`\n\n\";" + cmdOriginal;
				}

				//Execute OS Level Command
				var child = exec(cmd, function (error, stdout, stderr) {
					//stdout=stdout.split("\n");
					//var result = '{"stdout":' + stdout + ',"stderr":"' + stderr + '","cmd":"' + cmd + '"}';
					if (stderr == null || stderr.length <= 0) {
						res.writeHead(200, {
							'Content-Type': 'text/plain; charset=utf-8'
						});
						res.end(cmdServer.encrypt(stdout) + '\n');
					} else {
						res.writeHead(500, {
							'Content-Type': 'text/plain; charset=utf-8'
						});
						res.end(cmdServer.encrypt(stderr) + '\n\n' + cmdServer.encrypt(stdout) + '\n');
					}
				});
			} else {
				stderr = "CMD is mandatory";
				res.writeHead(412, {
					'Content-Type': 'text/plain; charset=utf-8'
				});
				res.end(stderr + '\n');
			}
			if (async == "true") {
				//var result = '{"stdout":"async request' + '' + '","stderr":"' + '' + '","cmd":"' + cmd + '"}';
				//res.end(result + '\n');
				res.writeHead(200, {
					'Content-Type': 'text/plain; charset=utf-8'
				});
				result = "ASYNC request started for " + cmd;
				res.end(cmdServer.encrypt(result) + '\n');
			}
		}).listen(port, host);
		console.log('Server running at ' + thisServerUrl);
	}
	this.stop = function () {
		process.exit(1);
	}

	this.writeFile = function (fname, content) {
		var fs = require('fs');
		fs.writeFile(fname, content, function (err) {
			if (err) {
				return console.log(err);
			}
			console.log("The file was saved!");
		});
	}

	this.runCmd = function (cmd, args, callBack) {
		var spawn = require('child_process').spawn;
		var child = spawn(cmd, args);
		var resp = "";

		child.stdout.on('data', function (buffer) {
			resp += buffer.toString()
		});
		child.stdout.on('end', function () {
			callBack(resp)
		});
	}

	this.encrypt = function (text) {
		if (!cmdServer.enableEncrypt) return text;
		cipher = crypto.createCipheriv(algorithm, cmdServer.password, iv);
		crypted = cipher.update(text, 'utf-8', 'hex');
		crypted += cipher.final('hex');

		return crypted;
	}

	this.decrypt = function (text) {
		var decipher = crypto.createDecipheriv(algorithm, cmdServer.password, iv);
		decrypted = decipher.update(text, 'hex', 'utf-8');
		decrypted += decipher.final('utf-8');
		return decrypted;
	}
}

//Other functions
function getIPAddress() {
	var interfaces = require('os').networkInterfaces();
	for (var devName in interfaces) {
		var iface = interfaces[devName];

		for (var i = 0; i < iface.length; i++) {
			var alias = iface[i];
			if (alias.family === 'IPv4' && alias.address !== '127.0.0.1' && !alias.internal)
				return alias.address;
		}
	}

	return '0.0.0.0';
}

if (masterIP == null) {
	masterIP = getIPAddress();
}
ip = masterIP;
s = new Server();
s.start(ip, hostPort, password, enableEncrypt);
