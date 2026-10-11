'use strict';
const $=id=>document.getElementById(id);
const launchParams=new URLSearchParams(location.hash.slice(1));
const suppliedToken=launchParams.get('token');
if(suppliedToken){
  sessionStorage.setItem('quantumtrace-token',suppliedToken);
  launchParams.delete('token');
  const fragment=launchParams.toString();
  history.replaceState(history.state,'',location.pathname+location.search+(fragment?'#'+fragment:''));
}
const token=suppliedToken||sessionStorage.getItem('quantumtrace-token')||'';
let language=sessionStorage.getItem('quantumtrace-language')||'pt', selectedFiles=[], runs=[], currentRun=null, busy=false, historyBusy=false, historyMessage=null, status=null;
let runRequest=0,comparisonRequest=0,refreshRequest=0;
const compared=new Set();
const staticNodes=[...document.querySelectorAll('[data-en]')].map(e=>({e,pt:[...e.childNodes].map(n=>n.cloneNode(true)),en:e.dataset.en}));
const strings={
  pt:{waiting:'A verificar o ambiente…',ready:'Ambiente pronto · TLS disponível',noTLS:'Código e JSON prontos · TShark em falta para PCAP',optional:'Leitura PEM/DER: componente cryptography opcional em falta.',
    none:'Nenhum ficheiro selecionado.',selection:(n,size)=>`${n} ficheiros selecionados · ${size} MiB`,choose:'Seleciona ficheiros ou uma pasta primeiro.',
    large:'A seleção excede o limite: 20 MiB por ficheiro, 80 MiB no total e 2000 ficheiros.',reading:'A preparar os ficheiros…',running:'Análise em curso…',detail:'Podes consultar o histórico enquanto os ficheiros são analisados. Capturas TLS podem demorar até 45 segundos por ficheiro.',
    connection:'Não foi possível contactar a app. Mantém a janela do terminal aberta e tenta atualizar.',session:'Reabre a app com INICIAR_APP.cmd para recuperar a sessão.',
    compare:'Incluir na comparação',history:(s)=>`${s.analysed_files} ficheiros analisados · ${s.non_offered_findings??s.total_findings-s.offered_findings} observações nos cartões`,
    cards:['Adicionadas','Deixaram de aparecer','Reclassificadas','Sem alteração'],same:'Mesmos dados suportados, mesma política e mesmas observações. Este resultado é esperado ao repetir a análise.',
    changed:'Os dados ou a cobertura mudaram. Uma observação que deixou de aparecer não comprova que uma vulnerabilidade foi corrigida.',policy:'As políticas de avaliação diferem; os índices não são diretamente comparáveis.',
    details:['Ver observações adicionadas','Ver observações que deixaram de aparecer','Ver observações reclassificadas'],emptychange:'Não há alterações neste grupo.',
    base:'Base',new:'Comparada',name:'Ex.: Configuração atual da equipa',total:'Observações; os números não representam ficheiros.',loading:'A abrir a análise…',
    delete:'Apagar',deleteLabel:label=>`Apagar a análise «${label}»`,
    confirmDelete:label=>`Apagar a análise «${label}» do histórico?\n\nOs ficheiros originais e os relatórios já descarregados mantêm-se. Esta ação não pode ser desfeita.`,
    confirmClear:'Apagar todas as análises guardadas, incluindo as que não aparecem nesta lista?\n\nOs ficheiros originais e os relatórios já descarregados mantêm-se. Esta ação não pode ser desfeita.',
    deleting:'A apagar do histórico…',deleted:'Análise apagada do histórico.',cleared:'Histórico limpo.'
  },
  en:{waiting:'Checking the environment…',ready:'Environment ready · TLS available',noTLS:'Code and JSON ready · TShark needed for PCAP',optional:'PEM/DER parsing: optional cryptography component unavailable.',
    none:'No files selected.',selection:(n,size)=>`${n} files selected · ${size} MiB`,choose:'Choose files or a folder first.',
    large:'Selection exceeds the limits: 20 MiB per file, 80 MiB total and 2000 files.',reading:'Preparing files…',running:'Analysis in progress…',detail:'You can browse history during analysis. TLS captures can take up to 45 seconds per file.',
    connection:'Could not reach the app. Keep the terminal window open and try refreshing.',session:'Restart the app with INICIAR_APP.cmd to restore the session.',
    compare:'Include in comparison',history:(s)=>`${s.analysed_files} analysed files · ${s.non_offered_findings??s.total_findings-s.offered_findings} card observations`,
    cards:['Added','No longer observed','Reclassified','Unchanged'],same:'Same supported data, policy and observations. This is expected when repeating an analysis.',
    changed:'Inputs or coverage changed. A removed observation does not prove a vulnerability was fixed.',policy:'Assessment policies differ; the indices are not directly comparable.',
    details:['Inspect added observations','Inspect removed observations','Inspect reclassified observations'],emptychange:'No changes in this group.',
    base:'Baseline',new:'Compared',name:'Example: Current team configuration',total:'These counts refer to observations, not files.',loading:'Opening the analysis…',
    delete:'Delete',deleteLabel:label=>`Delete analysis “${label}”`,
    confirmDelete:label=>`Delete analysis “${label}” from history?\n\nOriginal files and downloaded reports are kept. This cannot be undone.`,
    confirmClear:'Delete all saved analyses, including those not shown in this list?\n\nOriginal files and downloaded reports are kept. This cannot be undone.',
    deleting:'Deleting from history…',deleted:'Analysis deleted from history.',cleared:'History cleared.'
  }
};
function t(){return strings[language];}
function el(tag,text,cls){const e=document.createElement(tag);if(text!==undefined)e.textContent=text;if(cls)e.className=cls;return e;}
function error(message){$('error').textContent=message;$('error').hidden=!message;}
async function api(path,body,asText=false,method){
  const options={headers:{'X-QuantumTrace-Token':token}};
  if(body!==undefined){options.method='POST';options.headers['Content-Type']='application/json';options.body=JSON.stringify(body);}
  if(method)options.method=method;
  let response;try{response=await fetch(path,options);}catch{throw new Error(t().connection);}
  if(!response.ok){const result=await response.json().catch(()=>({}));throw new Error(response.status===403?t().session:(result.error||t().connection));}
  return asText?response.text():response.json();
}
function setBusy(value,message){busy=value;$('progress').hidden=!value;$('progress-title').textContent=message||t().running;$('progress-detail').textContent=t().detail;
  updateControls();renderHistory();
}
function updateControls(){const blocked=busy||historyBusy;
  ['demo','choose-files','choose-folder'].forEach(id=>$(id).disabled=blocked||(id==='demo'&&status&&!status.demo_available));$('analysis-name').disabled=blocked;$('analyse').disabled=blocked||!selectedFiles.length;
  $('refresh').disabled=historyBusy;['export-html','export-json'].forEach(id=>$(id).disabled=historyBusy||!currentRun);
}
function historyFeedback(message){historyMessage=message;$('history-feedback').textContent=message?t()[message]:'';$('history-feedback').hidden=!message;}
function showSelection(){const size=selectedFiles.reduce((sum,f)=>sum+f.size,0);$('selection').textContent=selectedFiles.length?t().selection(selectedFiles.length,(size/1048576).toFixed(2)):t().none;updateControls();}
function collect(input){error('');const files=[...input.files],size=files.reduce((sum,f)=>sum+f.size,0);
  if(files.length>2000||size>80*1048576||files.some(f=>f.size>20*1048576)){selectedFiles=[];error(t().large);}else selectedFiles=files;
  showSelection();
}
function readFile(file){return new Promise((resolve,reject)=>{const reader=new FileReader();reader.onload=()=>resolve(String(reader.result).split(',')[1]);reader.onerror=()=>reject(new Error(language==='pt'?'Não foi possível ler um dos ficheiros.':'Could not read an input file.'));reader.readAsDataURL(file);});}
async function analyse(source){
  if(busy||historyBusy)return;
  error('');historyFeedback(null);setBusy(true,source==='upload'?t().reading:t().running);
  try{
    const request={source,label:$('analysis-name').value.trim()||undefined};
    if(source==='upload'){
      if(!selectedFiles.length)throw new Error(t().choose);
      request.files=[];
      // Folder selection preserves nesting; remove only the picker root.
      for(const f of selectedFiles){const path=f.webkitRelativePath?f.webkitRelativePath.split('/').slice(1).join('/'):f.name;request.files.push({name:path,data:await readFile(f)});}
    }
    $('progress-title').textContent=t().running;
    const job=await api('/api/analyses',request);
    for(;;){const result=await api('/api/jobs/'+job.id);
      if(result.status==='failed')throw new Error(result.error);
      if(result.status==='completed'){await refresh();await openRun(result.run_id);break;}
      await new Promise(resolve=>setTimeout(resolve,700));
    }
  }catch(exc){error(exc.message);}finally{setBusy(false);}
}
function renderHistory(){
  const c=t();$('history-list').replaceChildren();$('history-empty').hidden=!!runs.length;
  runs.forEach(run=>{const row=el('div',undefined,'history-item'+(run.id===currentRun?' active':'')),b=el('button',run.label,'run-button');
    row.dataset.runId=run.id;b.disabled=historyBusy;b.addEventListener('click',()=>openRun(run.id).catch(exc=>error(exc.message)));row.append(b,el('p',new Date(run.created_at).toLocaleString(language==='pt'?'pt-PT':'en-GB')),el('p',c.history(run.summary)));
    const label=el('label'),check=el('input');check.type='checkbox';check.checked=compared.has(run.id);check.disabled=historyBusy||(compared.size>=2&&!check.checked);
    check.addEventListener('change',()=>{if(check.checked)compared.add(run.id);else compared.delete(run.id);renderHistory();});label.append(check,el('span',c.compare));row.append(label);$('history-list').append(row);
    const remove=el('button',c.delete,'delete-run danger');remove.disabled=busy||historyBusy;remove.setAttribute('aria-label',c.deleteLabel(run.label));remove.addEventListener('click',()=>removeHistory(run.id));row.append(remove);
  });$('compare').disabled=historyBusy||compared.size!==2;$('clear-history').disabled=busy||historyBusy||!runs.length;
}
function clearResult(){runRequest++;currentRun=null;$('report-frame').srcdoc='';$('report-frame').style.height='';$('result-title').textContent='';$('result-date').textContent='';$('result-section').hidden=true;$('welcome').hidden=false;updateControls();}
function clearComparison(){comparisonRequest++;lastComparison=null;lastPair=null;$('comparison').hidden=true;$('comparison-label').textContent='';$('comparison-stats').replaceChildren();$('comparison-details').replaceChildren();$('comparison-note').textContent='';}
async function removeHistory(id=null){
  if(busy||historyBusy)return;
  const run=id===null?null:runs.find(r=>r.id===id);if(id!==null&&!run)return;
  if(!window.confirm(run?t().confirmDelete(run.label):t().confirmClear))return;
  error('');historyBusy=true;runRequest++;comparisonRequest++;refreshRequest++;historyFeedback('deleting');updateControls();renderHistory();
  try{
    await api('/api/runs'+(id===null?'':'/'+id),undefined,false,'DELETE');
    if(id===null){runs=[];compared.clear();clearResult();clearComparison();}
    else{runs=runs.filter(r=>r.id!==id);compared.delete(id);if(currentRun===id)clearResult();if(lastPair?.some(r=>r.id===id))clearComparison();}
    historyFeedback(id===null?'cleared':'deleted');renderHistory();await refresh();
  }catch(exc){if(historyMessage==='deleting')historyFeedback(null);error(exc.message);}
  finally{historyBusy=false;updateControls();renderHistory();}
}
async function refresh(){const request=++refreshRequest,result=await api('/api/runs');if(request!==refreshRequest)return;runs=result.runs;const available=new Set(runs.map(r=>r.id));for(const id of compared)if(!available.has(id))compared.delete(id);renderHistory();}
async function openRun(id){
  if(historyBusy)return;
  error('');const request=++runRequest,html=await api('/api/runs/'+id+'/html',undefined,true),run=runs.find(r=>r.id===id);if(request!==runRequest)return;
  currentRun=id;$('result-title').textContent=run?.label||'QuantumTrace';$('result-date').textContent=run?new Date(run.created_at).toLocaleString(language==='pt'?'pt-PT':'en-GB'):'';
  $('report-frame').srcdoc=html;$('result-section').hidden=false;$('welcome').hidden=true;updateControls();renderHistory();
}
let lastComparison=null,lastPair=null;
function renderComparison(result,pair){
  const c=t();$('comparison').hidden=false;$('comparison-label').textContent=`${c.base}: ${pair[0].label} → ${c.new}: ${pair[1].label}`;
  $('comparison-stats').replaceChildren();[result.added_count,result.removed_count,result.reclassified_count,result.unchanged_count].forEach((count,i)=>{const box=el('div');box.append(el('strong',count),el('span',c.cards[i]));$('comparison-stats').append(box);});
  $('comparison-note').textContent=!result.same_policy?c.policy:(!result.same_supported_inputs||!result.same_file_coverage)?c.changed:(!result.added_count&&!result.removed_count&&!result.reclassified_count)?c.same:c.total;
  $('comparison-details').replaceChildren();[result.added,result.removed,result.reclassified].forEach((findings,i)=>{const details=el('details');details.append(el('summary',c.details[i]));
    if(!findings.length)details.append(el('p',c.emptychange,'small muted'));
    findings.forEach(f=>details.append(el('div',`${f.algorithm} · ${f.risk} · ${f.evidence.source} · ${f.evidence.locator}`,'finding-line')));$('comparison-details').append(details);
  });
}
async function compare(){if(historyBusy)return;error('');try{const pair=runs.filter(r=>compared.has(r.id)).sort((a,b)=>a.created_at.localeCompare(b.created_at));if(pair.length!==2)return;const request=++comparisonRequest,result=await api('/api/compare',{before:pair[0].id,after:pair[1].id});if(request!==comparisonRequest)return;lastComparison=result;lastPair=pair;renderComparison(lastComparison,pair);}catch(exc){error(exc.message);}}
async function download(kind){error('');try{const html=kind==='html',content=await api(`/api/runs/${currentRun}/${html?'download':'json'}`,undefined,html),blob=new Blob([html?content:JSON.stringify(content,null,2)],{type:html?'text/html':'application/json'}),url=URL.createObjectURL(blob),a=el('a');a.href=url;a.download=html?'QuantumTrace-report.html':'QuantumTrace-inventory.json';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);}catch(exc){error(exc.message);}}
function translate(){document.documentElement.lang=language;staticNodes.forEach(({e,pt,en})=>{e.replaceChildren();if(language==='pt')pt.forEach(n=>e.append(n.cloneNode(true)));else en.split('<br>').forEach((part,i)=>{if(i)e.append(el('br'));e.append(document.createTextNode(part));});});
  $('language').textContent=language==='pt'?'English':'Português';$('analysis-name').placeholder=t().name;
  $('runtime-text').textContent=status?(status.dependencies.tshark?t().ready:t().noTLS):t().waiting;
  if(status&&!status.dependencies.cryptography)$('runtime-text').append(el('br'),document.createTextNode(t().optional));
  showSelection();renderHistory();historyFeedback(historyMessage);if(lastComparison)renderComparison(lastComparison,lastPair);
  $('report-frame').contentWindow?.postMessage({type:'quantumtrace-language',language},'*');
}
$('choose-files').addEventListener('click',()=>$('files').click());$('choose-folder').addEventListener('click',()=>$('folder').click());
$('files').addEventListener('change',()=>collect($('files')));$('folder').addEventListener('change',()=>collect($('folder')));
$('demo').addEventListener('click',()=>analyse('demo'));$('analyse').addEventListener('click',()=>analyse('upload'));
$('refresh').addEventListener('click',()=>refresh().catch(exc=>error(exc.message)));$('compare').addEventListener('click',compare);
$('clear-history').addEventListener('click',()=>removeHistory());
$('close-comparison').addEventListener('click',()=>$('comparison').hidden=true);
$('export-html').addEventListener('click',()=>download('html'));$('export-json').addEventListener('click',()=>download('json'));
$('language').addEventListener('click',()=>{language=language==='pt'?'en':'pt';sessionStorage.setItem('quantumtrace-language',language);translate();});
function sendViewport(){const frame=$('report-frame');frame.contentWindow?.postMessage({type:'quantumtrace-viewport',top:-frame.getBoundingClientRect().top,height:window.innerHeight},'*');}
$('report-frame').addEventListener('load',()=>{$('report-frame').contentWindow?.postMessage({type:'quantumtrace-language',language},'*');sendViewport();});
let viewportScheduled=false;
['scroll','resize'].forEach(name=>window.addEventListener(name,()=>{if(!viewportScheduled){viewportScheduled=true;requestAnimationFrame(()=>{viewportScheduled=false;sendViewport();});}},{passive:true}));
window.addEventListener('message',event=>{if(event.source===$('report-frame').contentWindow&&event.data?.type==='quantumtrace-report-height'&&Number.isFinite(event.data.height))$('report-frame').style.height=Math.min(60000,Math.max(500,event.data.height+12))+'px';});
translate();
(async()=>{try{status=await api('/api/status');$('version').textContent=status.version;$('runtime').classList.toggle('warn',!status.dependencies.tshark);translate();setBusy(false);await refresh();if(runs.length)await openRun(runs[0].id);}catch(exc){error(exc.message);$('demo').disabled=true;$('runtime-text').textContent=t().connection;}})();
