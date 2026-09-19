#!/usr/bin/env node
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { chromium } from 'playwright';

const endpoint = process.argv[2];
if (!endpoint?.startsWith('ws://127.0.0.1:')) throw new Error('Expected a loopback fixture WebSocket URL');
const root = new URL('./node_modules/@novnc/novnc/', import.meta.url);
const server = createServer(async (req, res) => {
  if (req.url === '/') {
    res.setHeader('Content-Type', 'text/html');
    res.end(`<div id="display"></div><script type="module">
      import RFB from '/core/rfb.js';
      window.phase=0;
      const rfb=new RFB(document.getElementById('display'),${JSON.stringify(endpoint)});
      rfb.viewOnly=true; rfb.resizeSession=false;
      setInterval(()=>{
        const c=document.querySelector('canvas');
        if(!c || c.width*c.height!==2)return;
        const p=c.getContext('2d').getImageData(0,0,c.width,c.height).data;
        if(c.width===2 && c.height===1){
          if(window.phase===0 && p[0]===255 && p[1]===0 && p[2]===0 && p[5]===255)window.phase=1;
          if(window.phase===1 && p[0]===0 && p[1]===0 && p[2]===255 && p[5]===255)window.phase=2;
        }
        if(window.phase===2 && c.width===1 && c.height===2 && p[0]===255 && p[1]===255 && p[2]===255 && p[4]===0 && p[5]===0 && p[6]===255)window.phase=3;
      },10);
    </script>`);
    return;
  }
  try {
    const path = new URL('.' + req.url, root);
    if (!path.href.startsWith(root.href)) { res.writeHead(403).end(); return; }
    res.setHeader('Content-Type', 'text/javascript');
    res.end(await readFile(path));
  } catch { res.writeHead(404).end(); }
});
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
let browser;
try {
  browser = await chromium.launch({ headless: true });
  const page = await browser.newPage();
  page.on('pageerror', err => console.error(err));
  await page.goto(`http://127.0.0.1:${server.address().port}`);
  await page.waitForFunction(() => window.phase === 3, {}, { timeout: 15000 });
  console.log('noVNC 1.7.0 Chromium: initial frame, partial update and resize rendered');
} finally {
  if (browser) await browser.close();
  await new Promise(resolve => server.close(resolve));
}
