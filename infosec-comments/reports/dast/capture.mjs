import http from "node:http"; import fs from "node:fs"; import zlib from "node:zlib";
const out = process.argv[2];
http.createServer((req,res)=>{let b=[];req.on("data",d=>b.push(d)).on("end",()=>{let body=Buffer.concat(b);
 if(req.headers["content-encoding"]==="gzip"){try{body=zlib.gunzipSync(body)}catch{}}
 fs.appendFileSync(out, JSON.stringify({t:new Date().toISOString(),method:req.method,url:req.url,len:body.length,body:body.toString("utf8").slice(0,4000)})+"\n");
 res.writeHead(200,{"content-type":"application/json"});res.end("{}");});}).listen(18999,"127.0.0.1",()=>console.log("capture on 18999"));
