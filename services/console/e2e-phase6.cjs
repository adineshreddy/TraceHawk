const { chromium, expect } = require("@playwright/test");
const http = require("node:http"), fs = require("node:fs"), path = require("node:path");
const root = process.env.PROJECT_ROOT || "/workspace";
const out = path.join(root, "docs/phase-6");
const credentials = JSON.parse(fs.readFileSync(path.join(root, "tmp/credentials.json")));
const base = "http://127.0.0.1:3100";
(async () => {
  fs.mkdirSync(out, {recursive:true});
  const proxy = http.createServer((req,res) => {
    const upstream = http.request({hostname:"console",port:3100,path:req.url,method:req.method,headers:req.headers},r=>{
      res.writeHead(r.statusCode,r.headers); r.pipe(res);
    });
    upstream.on("error",()=>{res.writeHead(503);res.end();}); req.pipe(upstream);
  });
  await new Promise(resolve=>proxy.listen(3100,"127.0.0.1",resolve));
  const browser = await chromium.launch();
  const errors=[], rehearsals=[];
  let recordedVideo;
  try {
    for (let repeat=0;repeat<2;repeat++) {
      // Authenticate before creating the recorded page: passwords never appear in video.
      const context = await browser.newContext({viewport:{width:1440,height:1000},
        ...(repeat===0?{recordVideo:{dir:path.join(root,"tmp/demo-video"),size:{width:1440,height:1000}}}:{})});
      const auth = await context.request.post(base+"/api/v1/session/login",{
        headers:{Origin:base},data:{username:"operator",password:credentials.operator}});
      expect(auth.status()).toBe(200);
      const page=await context.newPage();
      page.on("pageerror",e=>errors.push(e.message));
      await page.goto(base);
      await expect(page.getByRole("heading",{name:"Network overview",exact:true})).toBeVisible();
      const hold = async ms => {if(repeat===0) await page.waitForTimeout(ms);};
      async function replay(scenario, expectedEvents, expectedAlerts, suppress=false) {
        await page.getByRole("button",{name:"Replay",exact:true}).click();
        await page.getByLabel("Scenario",{exact:true}).selectOption(scenario);
        await page.getByLabel("Playback speed",{exact:true}).selectOption("10");
        await page.getByLabel("Rule snapshot",{exact:true}).selectOption("phase2-rules-v1");
        if(suppress) await page.getByLabel("Authorize the lab scanner for this replay (suppress port-scan alert only)",{exact:true}).check();
        const posted=page.waitForResponse(r=>r.url().endsWith("/api/v1/runs")&&r.request().method()==="POST");
        await page.getByRole("button",{name:"Start replay",exact:true}).click();
        const response=await posted; expect(response.status()).toBe(202);
        const run=await response.json();
        await expect(page.getByRole("heading",{name:"Current run · completed",exact:true})).toBeVisible({timeout:45000});
        const overview=await page.request.get(base+"/api/v1/overview?scope_id="+run.scope_id);
        expect(overview.ok()).toBeTruthy();
        const counts=await overview.json();
        expect(counts.event_count).toBe(expectedEvents);
        expect(counts.open_alert_count).toBe(expectedAlerts);
        expect(counts.suppressed_alert_count).toBe(suppress?1:0);
        return {scenario,run_id:run.run_id,events:counts.event_count,actionable_alerts:counts.open_alert_count,suppressed:counts.suppressed_alert_count};
      }
      const controlled=await replay("phase0-controlled-network-v1",108,6);
      await page.screenshot({path:path.join(out,"overview.png"),fullPage:true});
      await hold(9000);
      await page.getByRole("button",{name:"Alerts",exact:true}).click();
      await page.getByLabel("Filter detector_id",{exact:true}).selectOption("dns_nxdomain_burst");
      await expect(page.locator("tbody tr")).toHaveCount(1);
      await page.getByRole("button",{name:"DNS NXDOMAIN burst",exact:true}).click();
      await expect(page.getByRole("heading",{name:"Supporting events (40)",exact:true})).toBeVisible();
      await page.screenshot({path:path.join(out,"investigation.png"),fullPage:true});
      await hold(11000);
      await page.getByLabel("Investigation reason",{exact:true}).fill("Reviewed the controlled DNS lab episode and its supporting events.");
      await page.getByRole("button",{name:"Acknowledge",exact:true}).click();
      await expect(page.getByText("Disposition saved: acknowledged",{exact:true})).toBeVisible();
      await hold(2500);
      await page.getByRole("button",{name:"192.0.2.30",exact:true}).click();
      await expect(page.getByRole("heading",{name:"Host event timeline",exact:true})).toBeVisible();
      await page.screenshot({path:path.join(out,"host.png"),fullPage:true});
      await hold(8000);
      await page.getByRole("button",{name:"Operations",exact:true}).click();
      await expect(page.getByText("detector-a",{exact:true}).first()).toBeVisible();
      await expect(page.getByText("detector-b",{exact:true}).first()).toBeVisible();
      await expect(page.getByRole("link",{name:"Open Grafana operations dashboard"})).toHaveAttribute("href","http://127.0.0.1:3101/d/tracehawk-operations");
      await page.screenshot({path:path.join(out,"operations.png"),fullPage:true});
      await hold(10000);
      await page.getByRole("button",{name:"Evaluation",exact:true}).click();
      await expect(page.locator("tbody tr")).toHaveCount(9);
      await expect(page.getByText(/Default enabled: no/)).toBeVisible();
      await expect(page.getByText(/500 events\/s × 600-second target: failed early/)).toBeVisible();
      await page.screenshot({path:path.join(out,"evaluation.png"),fullPage:true});
      await hold(10000);
      const benign=await replay("benign-network-v1",17,0);
      await expect(page.getByRole("button",{name:"DNS NXDOMAIN burst",exact:true})).toHaveCount(0);
      await page.screenshot({path:path.join(out,"benign.png"),fullPage:true});
      await hold(6500);
      const authorized=await replay("phase0-controlled-network-v1",108,5,true);
      await page.getByRole("button",{name:"Alerts",exact:true}).click();
      await page.getByLabel("Filter detector_id",{exact:true}).selectOption("");
      await page.getByLabel("Filter suppressed",{exact:true}).selectOption("true");
      await expect(page.locator("tbody tr")).toHaveCount(1);
      await page.getByRole("button",{name:"Possible vertical port scan",exact:true}).click();
      await expect(page.getByText("Suppressed · evidence retained",{exact:true})).toBeVisible();
      await expect(page.getByRole("heading",{name:"Supporting connections (24)",exact:true})).toBeVisible();
      await page.screenshot({path:path.join(out,"suppression.png"),fullPage:true});
      await hold(9000);
      await page.setViewportSize({width:390,height:844});
      expect(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth)).toBe(false);
      await page.screenshot({path:path.join(out,"mobile.png"),fullPage:true});
      rehearsals.push({repeat,controlled,benign,authorized,mobile_overflow:false});
      if(repeat===0) recordedVideo=page.video();
      await context.close();
      if(repeat===0) await recordedVideo.saveAs(path.join(out,"tracehawk-demo.webm"));
    }
    expect(errors).toHaveLength(0);
    const report={status:"passed",rehearsals,page_errors:errors,
      video:"tracehawk-demo.webm",video_note:"Silent automated Chromium walkthrough of actual local services. Authentication occurs before recording. Each rehearsal starts fresh replay scopes; existing database history is preserved."};
    fs.writeFileSync(path.join(out,"rehearsals.json"),JSON.stringify(report,null,2)+"\n");
    console.log(JSON.stringify(report,null,2));
  } finally {await browser.close();proxy.close();}
})().catch(e=>{console.error(e);process.exitCode=1;});
