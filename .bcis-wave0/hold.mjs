import http from 'node:http';
const port=Number(process.env.PORT||10000);
http.createServer((req,res)=>{res.writeHead(200,{'content-type':'application/json'});res.end(JSON.stringify({service:'bcis-wave0-migration-runner',status:'completed-or-inspect-logs'}));}).listen(port,'0.0.0.0');
