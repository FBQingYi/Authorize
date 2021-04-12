var http = require('http');
var fs = require('fs');
var path = require('path');
var querystring = require('querystring');
var app = http.createServer();
const url = require('url');
const util = require('util');
const crypto = require("crypto");
var validator = require('validator');

fs.stat('data', function (err, stats) {
    if (err != null) {
        fs.mkdir('data', function (error) {
            console.log('创建data文件夹成功')
            fs.appendFile("./data/data.json", '{}', (error) => { })
            fs.appendFile("./data/ban.json", '{}', (error) => { })
            fs.appendFile("./data/warrant.json", '{}', (error) => { })
        })
    }
})

//确认请求方法
app.on('request', function (req, res) {
    res.writeHead(200, {
        'content-type': 'text/html;charset=utf8'
    });
    let ip = getClientIp(req)
    let time = time_nian()
    let mypath = url.parse(req.url).pathname;
    if (req.method == 'POST') {
        let log_a = ''
        fs_log(log_a, ip)
        toPost(req, res, mypath, ip, time)
    } else {
        return false;
    }
})

//链接数据处理
function toPost(req, res, mypath, ip, time) {
    let post = '';
    req.on('data', function (chunk) {
        post += chunk;
    });
    req.on('end', function () {
        if (mypath == '/GetUUID' && post.length == 172) {
            const privateKey = fs.readFileSync("./privatekey.pem").toString('ascii');
            const decodeData = crypto.privateDecrypt(privateKey, Buffer.from(post.toString('base64'), 'base64'));
            post = decodeData.toString("utf8")
            if (!validator.isJSON(post) || post.indexOf("mac") == -1 || post.indexOf("port") == -1){
                let log_a = time + ' [ERR] ' + ip + '》》》请求数据出错！\n'
                fs_log(log_a, ip)
                console.log(time + ' [ERR] ' + ip + '》》》请求数据出错！')
                rsa('408', res)
            }else{
                GetUUID(post, ip, res)
            }
        } else if (mypath == '/favicon.ico') {
            return false;
        } else if (mypath == '/check' && post.length == 172) {
            const privateKey = fs.readFileSync("./privatekey.pem").toString('ascii');
            const decodeData = crypto.privateDecrypt(privateKey, Buffer.from(post.toString('base64'), 'base64'));
            post = decodeData.toString("utf8")
            if(!validator.isJSON(post) || post.indexOf("mac") == -1 || post.indexOf("port") == -1 || post.indexOf("uuid") == -1){
                let log_a = time + ' [ERR] ' + ip + '》》》请求数据出错！\n'
                fs_log(log_a, ip)
                console.log(time + ' [ERR] ' + ip + '》》》请求数据出错！')
                rsa('408', res)
            }else{
                check(post, ip, res)
            } 
        }
        else {
            let log_a = time + ' [ERR] ' + ip + '》》》请求数据出错！\n'
            fs_log(log_a, ip)
            console.log(time + ' [ERR] ' + ip + '》》》请求数据出错！')
            rsa('408', res)
        }
    });
}

//首次请求，返回UUID
function GetUUID(post, ip, res) {
    let data = JSON.parse(post);
    let mac = data.mac;
    let port = data.port;
    let time = time_nian();
    fs.readFile('./data/warrant.json', 'utf-8', function (err, warrant_data) {
        if (err != null) {
            let log_a = time + ' [ERR] ' + ip + '》》》读取文件出错！\n'
            fs_log(log_a, ip)
            console.log(time + ' [ERR] ' + ip + '》》》读取文件出错！');
            rsa('900', res)
        } else {
            //白名单ip直接通过
            let warrant = warrant_data.indexOf(ip)
            if (warrant != -1) {
                let log_a = time + ' [INF] ' + ip + '》》》白名单IP直接通过！！！\n'
                fs_log(log_a, ip)
                console.log(time + ' [INF] ' + ip + '》》》白名单IP直接通过！！！');
                rsa('1', res)
            } else {
                //进行黑名单判断
                fs.readFile('./data/ban.json', 'utf-8', function (err, ban_data) {
                    if (err != null) {
                        let log_a = time + ' [ERR] ' + ip + '》》》读取文件出错！\n'
                        fs_log(log_a, ip)
                        console.log(time + ' [ERR] ' + ip + '》》》读取文件出错！');
                        rsa('900', res)
                    } else {
                        let ban = ban_data.indexOf(ip)
                        if (ban != -1) {
                            let log_a = time + ' [ERR] ' + ip + '》》》黑名单用户请求授权被拒！！！\n'
                            fs_log(log_a, ip)
                            console.log(time + ' [ERR] ' + ip + '》》》黑名单用户请求授权被拒！！！')
                            rsa('500', res)
                        } else {
                            //通过黑名单判断，进行生成云uuid并返回
                            let uuid = UUID();
                            fs.readFile('./data/data.json', 'utf-8', function (err, data) {
                                if (err != null) {
                                    let log_a = time + ' [ERR] ' + ip + '》》》读取文件出错！\n'
                                    fs_log(log_a, ip)
                                    console.log(time + ' [ERR] ' + ip + '》》》读取文件出错！')
                                    rsa('900', res)
                                } else {
                                    let datac = JSON.parse(data)
                                    //写入授权相关数据判断是否首次获取
                                    if (datac[ip] == undefined || datac[ip] == null) {
                                        datac[ip] = { 密匙: uuid, 端口: port, 本地密匙: mac }
                                        let acca = JSON.stringify(datac, null, "\t");
                                        fs.writeFile('./data/data.json', acca, function (err) {
                                            if (err != null) {
                                                let log_a = time + ' [ERR] ' + ip + '》》》写入文件出错！\n'
                                                fs_log(log_a, ip)
                                                console.log(time + ' [ERR] ' + ip + '》》》写入文件出错！')
                                                rsa('800', res)
                                            } else {
                                                let log_a = time + ' [INF] 收到' + ip + '第一次授权认证》》本地密匙：' + mac + ' 端口：' + port + ' 生成UUID：' + uuid + ' IP地址：' + ip + ' \n'
                                                fs_log(log_a, ip)
                                                console.log(time + ' [INF] 收到' + ip + '第一次授权认证》》本地密匙：' + mac + ' 端口：' + port + ' 生成UUID：' + uuid + ' IP地址：' + ip)
                                                rsa(uuid, res)
                                            }
                                        })
                                    } else {
                                        let log_a = time + ' [ERR] ' + ip + '》》》重复获取uuid\n'
                                        fs_log(log_a, ip)
                                        console.log(time + ' [ERR] ' + ip + '》》》重复获取uuid');
                                        rsa('100', res)
                                    }
                                }
                            })
                        }
                    }
                })
            }
        }
    })
}

//授权验证
function check(post, ip, res) {
    let data = JSON.parse(post);
    let mac = data.mac;
    let port = data.port;
    let uuid = data.uuid;
    let time = time_nian();
    fs.readFile('./data/warrant.json', 'utf-8', function (err, warrant_data) {
        if (err != null) {
            let log_a = time + ' [ERR] ' + ip + '》》》读取文件出错！\n'
            fs_log(log_a, ip)
            console.log(time + ' [ERR] ' + ip + '》》》读取文件出错！');
            rsa('900', res)
        } else {
            //白名单ip直接通过
            let warrant = warrant_data.indexOf(ip)
            if (warrant != -1) {
                let log_a = time + ' [INF] ' + ip + '》》》白名单IP直接通过！！！\n'
                fs_log(log_a, ip)
                console.log(time + ' [INF] ' + ip + '》》》白名单IP直接通过！！！');
                rsa('1', res)
            } else {
                //判断黑名单
                fs.readFile('./data/ban.json', 'utf-8', function (err, ban_data) {
                    if (err != null) {
                        let log_a = time + ' [ERR] ' + ip + '》》》读取文件出错！\n'
                        fs_log(log_a, ip)
                        console.log(time + ' [ERR] ' + ip + '》》》读取文件出错！');
                        rsa('900', res)
                    } else {
                        let ban = ban_data.indexOf(ip);
                        if (ban != -1) {
                            let log_a = time + ' [ERR] ' + ip + '》》》黑名单用户请求授权被拒！！！\n'
                            fs_log(log_a, ip)
                            console.log(time + ' [ERR] ' + ip + '》》》黑名单用户请求授权被拒！！！')
                            rsa('500', res)
                        } else {
                            //通过黑名单判断进行授权
                            fs.readFile('./data/data.json', 'utf-8', function (err, data) {
                                if (err != null) {
                                    let log_a = time + ' [ERR] ' + ip + '》》》读取文件出错！\n'
                                    fs_log(log_a, ip)
                                    console.log(time + ' [ERR] ' + ip + '》》》读取文件出错！');
                                    rsa('900', res)
                                } else {
                                    //判断ip下是否有授权
                                    let datac = JSON.parse(data);
                                    if (datac[ip] != undefined || datac[ip] != null) {
                                        if (datac[ip].密匙 == uuid && datac[ip].端口 == port && datac[ip].本地密匙 == mac) {
                                            let log_a = time + ' [INF] ' + ip + '》》》授权成功！！！\n'
                                            fs_log(log_a, ip)
                                            console.log(time + ' [INF] ' + ip + '》》》授权成功！！！')
                                            rsa('1', res)
                                        } else {
                                            let log_a = time + ' [ERR] ' + ip + '》》》授权失败！！！相关IP下数据不匹配\n'
                                            fs_log(log_a, ip)
                                            console.log(time + ' [ERR] ' + ip + '》》》授权失败！！！相关IP下数据不匹配')
                                            rsa('400', res)
                                        }
                                    } else {
                                        let log_a = time + ' [ERR] ' + ip + '》》》授权失败！！！相关IP下没有数据\n'
                                        fs_log(log_a, ip)
                                        console.log(time + ' [ERR] ' + ip + '》》》授权失败！！！相关IP下没有数据')
                                        rsa('400', res)
                                    }
                                }
                            })
                        }
                    }
                })
            }
        }
    })
}

//加密函数并返回
function rsa(end_data, res) {
    const publicKey = fs.readFileSync("./publickey.pem");
    const encodeData = crypto.publicEncrypt(publicKey, Buffer.from(end_data));
    res.end(encodeData.toString("base64"));
}

//写入日志函数
function fs_log(log_a, ip) {
    let riqi = time_nian2()
    let time = time_nian();
    fs.appendFile("./data/" + riqi + "-log.txt", log_a, (error) => {
        if (error) {
            console.log(time + ' [ERR] ' + ip + '》》》写入日志出错！')
        }
    })
}

//年月日 时 分 秒
function time_nian() {
    var date = new Date();
    var myyear = date.getFullYear();
    var mymonth = date.getMonth() + 1;
    var myweekday = date.getDate();
    var curHours = date.getHours();
    var curMinutes = date.getMinutes();
    var Seconds = date.getSeconds();
    if (mymonth < 10) {
        mymonth = "0" + mymonth;
    }
    if (myweekday < 10) {
        myweekday = "0" + myweekday;
    }
    if (curMinutes < 10) {
        curMinutes = "0" + curMinutes;
    }
    if (Seconds < 10) {
        Seconds = "0" + Seconds;
    }
    return (myyear + "-" + mymonth + "-" + myweekday + " " + curHours + ":" + curMinutes + ":" + Seconds);
}

//年月日
function time_nian2() {
    var date = new Date();
    var myyear = date.getFullYear();
    var mymonth = date.getMonth() + 1;
    var myweekday = date.getDate();
    var curHours = date.getHours();
    var curMinutes = date.getMinutes();
    var Seconds = date.getSeconds();
    if (mymonth < 10) {
        mymonth = "0" + mymonth;
    }
    if (myweekday < 10) {
        myweekday = "0" + myweekday;
    }
    if (curMinutes < 10) {
        curMinutes = "0" + curMinutes;
    }
    if (Seconds < 10) {
        Seconds = "0" + Seconds;
    }
    return (myyear + "-" + mymonth + "-" + myweekday);
}

function UUID() {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function (c) {
        var r = Math.random() * 16 | 0,
            v = c == 'x' ? r : (r & 0x3 | 0x8);
        return v.toString(16);
    });
}

function getClientIp(req) {
    let ip = req.headers['x-forwarded-for'] || // 判断是否有反向代理 IP
        req.connection.remoteAddress || // 判断 connection 的远程 IP
        req.socket.remoteAddress || // 判断后端的 socket 的 IP
        '获取失败';
    return ip.replace('::ffff:', '');
}

app.listen(5698, function () {
    let time = time_nian();
    let ip = '127.0.0.1'
    let log_a = time + ' [INF] 》》》授权系统加载成功！！0.2.0\n'
    fs_log(log_a, ip)
    console.log(time + ' [INF] 》》》授权系统加载成功！！0.2.0');
});