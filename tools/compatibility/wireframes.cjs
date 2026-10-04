const {chromium} = require('/work/tmp/phase0/node_modules/playwright');
(async()=>{
 const browser=await chromium.launch({headless:true,args:['--no-sandbox']});
 const page=await browser.newPage({viewport:{width:1440,height:1050}});
 const errors=[];page.on('pageerror',e=>errors.push(e.message));
 await page.goto('file:///work/docs/phase-0/console-wireframes.html');
 await page.screenshot({path:'/work/docs/evidence/wireframe-overview.png',fullPage:true});
 for(const id of ['alerts','detail','host','rules','replay','health']){
  await page.locator(`button[data-screen="${id}"]`).click();
  if(!await page.locator(`#${id}`).isVisible())throw Error(id);
 }
 await page.locator('button[data-screen="detail"]').click();
 await page.screenshot({path:'/work/docs/evidence/wireframe-investigation.png',fullPage:true});
 await page.setViewportSize({width:390,height:844});
 for(const id of ['overview','alerts','detail','host','rules','replay','health']){
  await page.locator(`button[data-screen="${id}"]`).click();
  if(!await page.locator(`#${id}`).isVisible())throw Error(`Mobile navigation: ${id}`);
  if(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth))throw Error(`Mobile overflow: ${id}`);
 }
 if(errors.length)throw Error(errors.join('\n'));
 require('fs').writeFileSync('/work/docs/evidence/wireframes.json',JSON.stringify({status:'passed',screens:7,desktop:'1440x1050',mobile:'390x844',page_errors:errors,limitations:['Static design navigation only; no application behavior tested.']},null,2)+'\n');
 await browser.close();console.log('Seven wireframe screens and mobile layout passed');
})();
