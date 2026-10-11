'use strict';
const data = JSON.parse(document.getElementById('data').textContent);
const $ = id => document.getElementById(id);
const s = data.summary;
const embedded = document.body.classList.contains('embedded');
let language = embedded ? 'pt' : 'en', pageIndex = 0, priorityPage = 0;
const findingById = new Map(data.findings.map(f=>[f.id,f]));
let viewport = {top:0,height:800};
const pageSize = 50;
// Translated labels must not change the machine values of the filters.
['risk','observation'].forEach(id=>[...$(id).options].forEach(o=>{o.value=o.value;}));
const copy = {
  pt: {critical:'Crítico',medium:'Intermédio',resilient:'Resiliente',unknown:'Por rever',
    inspect:'Ver evidência',close:'Fechar',missing_parameters:'Parâmetros em falta',missing_context:'Contexto em falta',
    policy_gap:'Regra por implementar',legacy_variant:'Versão antiga por confirmar',unrecognised_primitive:'Algoritmo por identificar',unspecified:'Motivo por esclarecer',
    configured:'Configurado', 'static-call':'Chamada no código',offered:'Oferecido',negotiated:'Negociado','key-material':'Chave pública','certificate-signature':'Assinatura do certificado',
    cards:'Observações dos cartões',all:'Todas as observações',offers:'Apenas ofertas TLS',allrisk:'Todos os níveis',allobs:'Todos os tipos de evidência',
    search:'Pesquisar algoritmo, ficheiro, evidência ou sessão',equation:(total,cards,offers)=>`${total} observações = ${cards} nos cartões + ${offers} ofertas TLS`,
    counting:'Os números contam ocorrências de primitivas, não ficheiros ou sistemas. Uma opção oferecida não prova que foi negociada.',
    score:v=>v===null?'Índice de exposição: indisponível':`Índice de exposição das primitivas: ${v} / 100`,
    scoreDetail:`${s.rated_findings} classificadas · ${s.unknown_findings} por rever · ${s.offered_findings} ofertas excluídas. Pesos: crítico 100, intermédio 50, resiliente 0; média apenas das classificadas.`,
    review:n=>n?`${n} observações dos cartões precisam de revisão. Cada caso indica o que falta; a classificação não é forçada.`:'Não há observações dos cartões por rever. Consulta também a cobertura e os limites da análise.',
    results:(n,total,page,pages)=>`${n} de ${total} observações na seleção · página ${page} de ${pages}`,
    coverage:`${s.analysed_files} analisados · ${s.partial_files} parciais · ${s.error_files} com erros · ${s.unsupported_files} fora dos formatos suportados · ${s.elapsed_seconds} segundos`,
    incomplete:'Cobertura incompleta. Existem ficheiros com erros ou análise parcial; consulta a cobertura antes de interpretar os totais.',
    network:(n,h)=>`${n} sessões com mecanismos selecionados · ${h} com grupos híbridos. São observações ao nível dos componentes.`,
    empty:'Sem resultados para estes filtros. A ausência de resultados não prova segurança.', previous:'Página anterior',next:'Página seguinte',download:'Descarregar inventário JSON',
    shown:n=>`Mostramos os primeiros ${n} casos. Filtra «Por rever» para consultar os restantes.`,
    labels:['Mecanismo','Classificação','Próximo passo','Informação em falta','Motivo da revisão','Regra','Modelo','Suposições','Confiança na evidência','Função','Normas','Questão clássica','Contexto','Limites'],
    docs:'Documentação de referência',notassigned:'Não atribuído',notrecorded:'Não registado',notreviewed:'Não avaliado além das verificações suportadas',global:'Consulta os limites gerais',
  },
  en: {critical:'Critical',medium:'Medium',resilient:'Resilient',unknown:'Needs review',
    inspect:'Inspect evidence',close:'Close',missing_parameters:'Missing parameters',missing_context:'Missing context',
    policy_gap:'Policy coverage gap',legacy_variant:'Legacy variant to verify',unrecognised_primitive:'Unrecognised primitive',unspecified:'Unspecified review reason',
    configured:'Configured','static-call':'Static call',offered:'Offered',negotiated:'Negotiated','key-material':'Public key','certificate-signature':'Certificate signature',
    cards:'Card observations',all:'All observations',offers:'TLS offers only',allrisk:'All risk tiers',allobs:'All evidence types',
    search:'Search algorithm, source, evidence or session',equation:(total,cards,offers)=>`${total} observations = ${cards} in cards + ${offers} TLS offers`,
    counting:'Counts refer to primitive occurrences, not files or systems. An offered option does not prove negotiated use.',
    score:v=>v===null?'Exposure index: unavailable':`Primitive exposure index: ${v} / 100`,
    scoreDetail:`${s.rated_findings} rated · ${s.unknown_findings} need review · ${s.offered_findings} offers excluded. Weights: critical 100, medium 50, resilient 0; mean over rated observations.`,
    review:n=>n?`${n} card observations need review. Each case states the missing information; classifications are not forced.`:'No card observations need review. Inspect input coverage and analysis limits as well.',
    results:(n,total,page,pages)=>`${n} of ${total} observations in scope · page ${page} of ${pages}`,
    coverage:`${s.analysed_files} analysed · ${s.partial_files} partial · ${s.error_files} errors · ${s.unsupported_files} outside supported formats · ${s.elapsed_seconds} seconds`,
    incomplete:'Incomplete coverage. Some files have errors or partial analysis; inspect coverage before interpreting the totals.',
    network:(n,h)=>`${n} sessions with selected mechanisms · ${h} with hybrid groups. This is component-level evidence.`,
    empty:'No matching findings. No findings is not proof of security.',previous:'Previous page',next:'Next page',download:'Download inventory JSON',
    shown:n=>`Showing the first ${n} cases. Filter “Needs review” to inspect the rest.`,
    labels:['Mechanism','Classification','Next step','Missing information','Review reason','Rule','Model','Assumptions','Evidence confidence','Role','Standards','Classical concern','Context','Caveats'],
    docs:'Source documentation',notassigned:'Not assigned',notrecorded:'Not recorded',notreviewed:'Not evaluated beyond supported checks',global:'See global analysis limits',
  }
};
const translations = {
  'Critical observations':'Observações críticas','Medium policy tier':'Nível intermédio da política','Resilient observations':'Observações resilientes','Needs review':'Por rever',
  'Classical public-key exposure':'Exposição de chave pública clássica','Challenge classification':'Classificação da política','Component-level evidence only':'Evidência apenas dos componentes','Unknown parameters or policy gaps':'Parâmetros em falta ou lacunas nas regras',
  'TLS sessions':'Sessões TLS','Inspect sessions and packet evidence':'Ver sessões e evidência dos pacotes',
  'Review queue':'Casos por rever','Cryptographic observations':'Observações criptográficas','Input coverage':'Cobertura dos ficheiros','Limits and unresolved evidence':'Limites e evidência por esclarecer','Assessment policy':'Política de avaliação','See policy and limits':'Ver política e limites',
  'Primitive':'Primitiva','Tier':'Nível','Observation':'Observação','Source / locator':'Ficheiro / localização','Evidence':'Evidência','Details':'Detalhes','Source':'Ficheiro','Status':'Estado','Findings':'Observações',
  'Stream / source':'Sessão / ficheiro','Server endpoint':'Servidor','Protocol':'Protocolo','Selected cipher':'Cifra selecionada','Selected group':'Grupo selecionado','Packet':'Pacote',
  'Inspect TLS offers':'Ver ofertas TLS',
  'This heuristic is not a security certification. A resilient primitive does not establish system resilience. Offered mechanisms are excluded from the index.':'Este índice não é uma certificação de segurança. Uma primitiva resiliente não comprova a resiliência do sistema. As ofertas ficam fora do índice.',
  'Selected mechanisms are observed in ServerHello. A critical classical component does not prove a hybrid group is broken. Authentication and complete session resilience are not established by these messages.':'Os mecanismos selecionados são observados no ServerHello. Uma componente clássica crítica não prova que o grupo híbrido está comprometido. Estes dados não comprovam a autenticação ou a resiliência da sessão completa.',
  'Tiers describe individual primitives. Missing information stays under review. Hash rules are a project extension, not NIST categories; a classical component does not determine the security of a hybrid group.':'Os níveis descrevem primitivas individuais. A informação em falta fica por rever. As regras dos hashes são uma extensão do projeto, sem categorias NIST; uma componente clássica não determina a segurança de um grupo híbrido.',
  'Priorities by file or resource':'Prioridades por ficheiro ou recurso',
  'How this inspection order works':'Como funciona esta ordem de revisão',
  'This is a technical inspection order. Business impact, asset ownership and confidentiality lifetime are not known, so it is not a complete enterprise risk ranking.':'Esta é uma ordem técnica de revisão. Faltam impacto no negócio, responsáveis e tempo de confidencialidade; não é um ranking completo de risco empresarial.'
};
const staticNodes = [...document.querySelectorAll('h2,th,.card span,summary,.notice p,.section>p,#show-offers')]
  .filter(e => translations[e.textContent.trim()]).map(e => [e,e.textContent.trim()]);
function el(tag,text,cls) {const e=document.createElement(tag);if(text!==undefined)e.textContent=text;if(cls)e.className=cls;return e;}
function t() {return copy[language];}
function resize() {if(embedded) parent.postMessage({type:'quantumtrace-report-height',height:Math.ceil(document.querySelector('main').getBoundingClientRect().height)},'*');}
function inspect(f) {
  const c=t(),a=f.assessment||{}; $('finding-title').textContent=f.algorithm+' · '+c[f.risk];$('details').replaceChildren();
  const dl=el('dl'),values=[f.quantum_mechanism,f.explanation,f.recommendation,(f.missing_information||[]).join('; ')||'—',c[f.review_reason]||'—',a.rule_id||c.notassigned,a.model||c.notassigned,(a.assumptions||[]).join(' ')||'—',f.confidence,f.role,(f.standards||[]).join(', ')||c.notassigned,f.classical_warning||c.notreviewed,f.context?JSON.stringify(f.context,null,2):c.notrecorded,(f.caveats||[]).join(' ')||c.global];
  values.forEach((v,i)=>dl.append(el('dt',c.labels[i]),el('dd',v)));$('details').append(dl);
  if(a.query_exponent_bits!==undefined&&a.query_exponent_bits!==null) $('details').append(el('p',`Generic query exponent: ${a.query_exponent_bits} bits · project target: ${a.target_bits} bits`, 'small muted'));
  (f.references||[]).filter(url=>/^https:\/\//.test(url)).forEach(url=>{const p=el('p'),a=el('a',c.docs+' ↗','reference-link');a.href=url;a.title=url;a.target='_blank';a.rel='noopener noreferrer';p.append(a);$('details').append(p);});
  placeDialog();
  if($('finding-dialog').showModal) $('finding-dialog').showModal();else $('finding-dialog').setAttribute('open','');
}
function placeDialog() {
  // The expanded iframe can be taller than the visible browser viewport.
  // Keep evidence dialogs in the visible portion of the parent page.
  if(embedded){const d=$('finding-dialog');d.style.position='absolute';d.style.margin='0 auto';d.style.top=Math.max(16,viewport.top+20)+'px';d.style.maxHeight=Math.max(200,viewport.height-40)+'px';}
}
function render() {
  const c=t(),query=$('search').value.toLowerCase(),risk=$('risk').value,obs=$('observation').value,scope=$('scope').value;
  const base=data.findings.filter(f=>scope==='all'||(scope==='offered'?f.observation==='offered':f.observation!=='offered'));
  const shown=base.filter(f=>(!risk||f.risk===risk)&&(!obs||f.observation===obs)&&JSON.stringify(f).toLowerCase().includes(query));
  pageIndex=Math.min(Math.max(0,pageIndex),Math.max(0,Math.ceil(shown.length/pageSize)-1));
  $('previous').disabled=pageIndex===0;$('next').disabled=(pageIndex+1)*pageSize>=shown.length;
  $('rows').replaceChildren();$('empty').hidden=shown.length>0;
  $('results').textContent=c.results(shown.length,base.length,pageIndex+1,Math.max(1,Math.ceil(shown.length/pageSize)));
  shown.slice(pageIndex*pageSize,(pageIndex+1)*pageSize).forEach(f=>{
    const tr=el('tr'),size=f.key_bits?` · ${f.key_bits} bits${f.algorithm.startsWith('PBKDF2')?' output':''}`:'';
    tr.append(el('td',f.algorithm+size));const tier=el('td');tier.append(el('span',c[f.risk],'badge '+f.risk));tr.append(tier,el('td',c[f.observation]||f.observation));
    const source=el('td');source.append(el('code',f.evidence.source+'\n'+f.evidence.locator));tr.append(source,el('td',f.evidence.detail));
    const action=el('td'),button=el('button',c.inspect,'small');button.addEventListener('click',()=>inspect(f));action.append(button);tr.append(action);$('rows').append(tr);
  });resize();
}

const priorityLabels = {
  en:{source:'Evidence source',mechanisms:'Mechanisms',reason:'Why review',next:'Next step',evidence:'Evidence',offers:'offered capabilities kept separate',details:'Inspect supporting evidence and other actions',
    search:'Search file, resource or mechanism',actions:['All actions','Public-key migration','Hybrid review','Missing information','Policy review','Offered capabilities'],
    titles:{'public-key-migration':'Plan public-key migration','hybrid-review':'Review the hybrid construction','missing-information':'Resolve missing information','deprecated-review':'Review deprecated cryptography','hash-policy-review':'Review the project hash model','symmetric-policy-review':'Review symmetric protection','verify-resilient-component':'Verify deployment and surrounding mechanisms','offered-capability':'Inventory offered capabilities'},
    method:'Classical public-key actions consider selected, configured, public-key/certificate and static evidence in that order. Hybrid construction review, missing information and policy checks are separate actions. Offers are inventory-only; this order has no business-impact score.',
    results:(n,total,page,pages)=>`${n} of ${total} resources · page ${page} of ${pages}`,empty:'No resources match these filters.'},
  pt:{source:'Origem da evidência',mechanisms:'Mecanismos',reason:'Motivo da revisão',next:'Próximo passo',evidence:'Evidência',offers:'capacidades oferecidas indicadas separadamente',details:'Ver evidências e outras ações',
    search:'Pesquisar ficheiro, recurso ou mecanismo',actions:['Todas as ações','Migração de chave pública','Revisão de híbridos','Informação em falta','Revisão da política','Capacidades oferecidas'],
    titles:{'public-key-migration':'Planear migração de chave pública','hybrid-review':'Rever a construção híbrida','missing-information':'Resolver informação em falta','deprecated-review':'Rever criptografia obsoleta','hash-policy-review':'Rever o modelo de hashes do projeto','symmetric-policy-review':'Rever proteção simétrica','verify-resilient-component':'Verificar utilização e mecanismos associados','offered-capability':'Inventariar capacidades oferecidas'},
    method:'As ações de chave pública consideram primeiro seleção observada, depois configuração, chave pública/certificado e chamadas no código. Híbridos, informação em falta e regras têm ações distintas. As ofertas são apenas inventário; esta ordem não calcula impacto no negócio.',
    results:(n,total,page,pages)=>`${n} de ${total} recursos · página ${page} de ${pages}`,empty:'Nenhum recurso corresponde aos filtros.'}
};
function renderPriorities() {
  const c=t(),p=priorityLabels[language],all=data.priorities?.groups||[],query=$('priority-search').value.toLowerCase(),kind=$('priority-filter').value;
  const matches=a=>!kind||(kind==='policy'?['deprecated-review','hash-policy-review','symmetric-policy-review'].includes(a.kind):a.kind===kind);
  const shown=all.filter(g=>g.actions.some(matches)&&JSON.stringify(g).toLowerCase().includes(query));
  const size=6,pages=Math.max(1,Math.ceil(shown.length/size));priorityPage=Math.min(Math.max(0,priorityPage),pages-1);
  $('priority-search').placeholder=p.search;[...$('priority-filter').options].forEach((o,i)=>o.textContent=p.actions[i]);
  $('priority-results').textContent=p.results(shown.length,all.length,priorityPage+1,pages);$('priority-method').textContent=p.method;
  $('priority-previous').textContent=c.previous;$('priority-next').textContent=c.next;
  $('priority-previous').disabled=priorityPage===0;$('priority-next').disabled=priorityPage===pages-1;
  $('priority-list').replaceChildren();
  if(!shown.length)$('priority-list').append(el('p',p.empty,'muted'));
  shown.slice(priorityPage*size,(priorityPage+1)*size).forEach(g=>{
    const card=el('article',undefined,'priority-card'),actions=g.actions.filter(matches),primary=actions[0];
    card.dataset.resourceId=g.id;card.append(el('h3',p.titles[primary.kind]||primary.title));
    card.append(el('p',p.source+': '+g.source,'small priority-source'));
    if(g.resource_kind!=='file')card.append(el('p',(g.resource_kind==='tls-session'?'TLS session: ':'Resource: ')+g.resource,'small priority-source'));
    card.append(el('p',Object.entries(g.evidence_counts).map(([state,n])=>(c[state]||state)+': '+n).join(' · '),'small muted'));
    const names=[...new Set(g.mechanisms.map(m=>m.hybrid_group||m.algorithm+(m.key_bits?' · '+m.key_bits+' bits'+(m.algorithm.startsWith('PBKDF2')?' output':''):'')))];
    card.append(el('p',p.mechanisms+': '+(names.join(', ')||p.offers),'small'));
    if(g.offered_mechanisms?.length)card.append(el('p',(c.offered||'Offered')+': '+g.offered_mechanisms.map(m=>m.algorithm+(m.key_bits?' '+m.key_bits+' bits':'')).join(', '),'small muted'));
    card.append(el('p',p.reason+': '+primary.reason,'small'),el('p',p.next+': '+primary.next_step,'small priority-next-step'));
    const details=el('details');details.append(el('summary',p.details));
    actions.forEach(a=>{
      const row=el('div',undefined,'priority-action');row.append(el('strong',(p.titles[a.kind]||a.title)+' · '+(c[a.observation]||a.observation)));
      if(a!==primary)row.append(el('p',p.reason+': '+a.reason,'small'),el('p',p.next+': '+a.next_step,'small'));
      const select=el('select'),ids=a.finding_ids.filter(id=>findingById.has(id));select.setAttribute('aria-label',p.evidence);
      ids.forEach(id=>{const f=findingById.get(id),option=el('option',f.algorithm+(f.key_bits?' '+f.key_bits+' bits':'')+' · '+f.evidence.locator);option.value=id;select.append(option);});
      const button=el('button',c.inspect,'small');button.disabled=!ids.length;button.addEventListener('click',()=>inspect(findingById.get(select.value)));
      const controls=el('div',undefined,'priority-evidence');controls.append(select,button);row.append(controls);details.append(row);
    });card.append(details);$('priority-list').append(card);
  });resize();
}

function overview() {
  const c=t();document.documentElement.lang=language;
  staticNodes.forEach(([node,english])=>node.textContent=language==='pt'?translations[english]:english);
  ['critical','medium','resilient','unknown'].forEach(k=>$(k).textContent=s.risk_counts[k]||0);
  $('generated').textContent=new Date(data.generated_at).toLocaleString(language==='pt'?'pt-PT':'en-GB');
  $('count-equation').textContent=c.equation(s.total_findings,s.non_offered_findings??(s.total_findings-s.offered_findings),s.offered_findings);
  $('count-explain').textContent=c.counting;$('score').textContent=c.score(s.quantum_risk_score);$('score-detail').textContent=c.scoreDetail;$('coverage').textContent=c.coverage;
  $('coverage-alert').hidden=!(s.partial_files||s.error_files);$('coverage-alert').textContent=c.incomplete;
  $('language').textContent=language==='pt'?'English':'Português';$('close-dialog').textContent=c.close;
  $('search').placeholder=c.search;$('previous').textContent=c.previous;$('next').textContent=c.next;$('download').textContent=c.download;$('empty').textContent=c.empty;
  [...$('scope').options].forEach((o,i)=>o.textContent=[c.cards,c.all,c.offers][i]);
  [...$('risk').options].forEach(o=>o.textContent=o.value?c[o.value]:c.allrisk);
  [...$('observation').options].forEach(o=>o.textContent=o.value?(c[o.value]||o.value):c.allobs);
  const unknown=data.findings.filter(f=>f.risk==='unknown'&&f.observation!=='offered');
  $('review-explain').textContent=c.review(unknown.length);$('review-list').replaceChildren();
  unknown.slice(0,50).forEach(f=>{const row=el('div',undefined,'review-item'),text=el('div');
    text.append(el('strong',f.algorithm+' · '+(c[f.review_reason]||c.unspecified)),el('p',f.evidence.source+' · '+f.evidence.locator,'small muted'),el('p',(f.missing_information||[]).join('; '),'small'));
    const b=el('button',c.inspect,'small');b.addEventListener('click',()=>inspect(f));row.append(text,b);$('review-list').append(row);
  });if(unknown.length>50) $('review-list').append(el('p',c.shown(50),'small muted'));
  const sessions=new Map();
  data.findings.filter(f=>f.context&&f.context.session&&f.context.event==='server_hello').forEach(f=>{
    const c=f.context,key=f.evidence.source+'|'+c.session,row=sessions.get(key)||{source:f.evidence.source,session:c.session,ciphers:new Set(),groups:new Set(),protocol:c.protocol,endpoint:(c.source_ip||'Unknown')+(c.source_port?':'+c.source_port:''),frame:c.frame||'Unknown',hybrid:false};
    if(c.mechanism&&c.mechanism.startsWith('TLS_')) row.ciphers.add(c.mechanism);else if(c.mechanism) row.groups.add(c.mechanism);
    row.hybrid=row.hybrid||!!c.hybrid_components;sessions.set(key,row);
  });
  $('network').hidden=!sessions.size;$('sessions').replaceChildren();
  if(sessions.size){$('network-summary').textContent=c.network(sessions.size,[...sessions.values()].filter(r=>r.hybrid).length);
    sessions.forEach(r=>{const tr=el('tr');[r.session+' · '+r.source,r.endpoint,r.protocol,[...r.ciphers].join(', ')||c.notrecorded,[...r.groups].join(', ')||c.notrecorded,r.frame].forEach(v=>tr.append(el('td',v)));$('sessions').append(tr);});}
  renderPriorities();render();
}
data.files.forEach(f=>{const tr=el('tr');[f.source,f.status,f.findings].forEach(v=>tr.append(el('td',v)));$('files').append(tr);});
[...data.policy.limitations,...data.warnings.map(w=>w.source+': '+w.message)].forEach(w=>$('warnings').append(el('li',w)));
$('policy').append(el('pre',JSON.stringify(data.policy,null,2),'small'));
['priority-search','priority-filter'].forEach(id=>$(id).addEventListener('input',()=>{priorityPage=0;renderPriorities();}));
$('priority-previous').addEventListener('click',()=>{priorityPage--;renderPriorities();});$('priority-next').addEventListener('click',()=>{priorityPage++;renderPriorities();});
['search','risk','observation','scope'].forEach(id=>$(id).addEventListener('input',()=>{pageIndex=0;render();}));
$('previous').addEventListener('click',()=>{pageIndex--;render();});$('next').addEventListener('click',()=>{pageIndex++;render();});
$('show-offers').addEventListener('click',()=>{$('scope').value='offered';$('risk').value='';$('observation').value='';$('search').value='';pageIndex=0;render();$('scope').scrollIntoView?.({block:'center',behavior:'smooth'});});
$('language').addEventListener('click',()=>{language=language==='en'?'pt':'en';overview();});
$('close-dialog').addEventListener('click',()=>{if($('finding-dialog').close)$('finding-dialog').close();else $('finding-dialog').removeAttribute('open');});
$('download').addEventListener('click',()=>{const blob=new Blob([JSON.stringify(data,null,2)],{type:'application/json'}),url=URL.createObjectURL(blob),a=el('a');a.href=url;a.download='quantumtrace-inventory.json';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);});
if(embedded){window.addEventListener('message',event=>{
  if(event.source!==parent)return;
  if(event.data?.type==='quantumtrace-language'&&['en','pt'].includes(event.data.language)){language=event.data.language;overview();}
  if(event.data?.type==='quantumtrace-viewport'&&Number.isFinite(event.data.top)&&Number.isFinite(event.data.height)){viewport={top:Math.max(0,event.data.top),height:Math.max(240,event.data.height)};if($('finding-dialog').open)placeDialog();}
});if(window.ResizeObserver)new ResizeObserver(resize).observe(document.body);}
overview();
