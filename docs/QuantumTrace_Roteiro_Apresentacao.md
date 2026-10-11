# QuantumTrace: presentation script and live demo

Hidden Signal. QuantumTrace 0.3.3. English speech, with Portuguese stage directions. Prepared on 10 October 2026.

## 1. Como usar este roteiro

A versão principal prevê cinco minutos: cinco slides visíveis e uma demonstração ao vivo. Os slides 6, 7 e 8 são apoio para perguntas e ficam ocultos no modo normal. O guião de três minutos está na secção 4. Os tempos são metas de ensaio, não uma duração medida da tua fala.

O que dizes ao júri está em inglês, nos parágrafos identificados como Fala. As ações estão em português. As notas do PowerPoint também incluem a fala e as ações em inglês. Na apresentação não precisas de mostrar a árvore dos 97 ficheiros. Usa o guia da pasta para estudar e responder a perguntas técnicas.

O PowerPoint é um ficheiro editável e o PDF dos slides é uma alternativa offline. Este pacote não instala a app no teu Windows nem submete o projeto à organização.

## 2. Preparação antes de entrar

1. Abre a pasta extraída com INICIAR_APP.cmd, quantumtrace, data e reports. Inicia a app e mantém o terminal aberto.
2. Muda a interface para English. Confirma também os rótulos do relatório. Fecha separadores e notificações que não precisas.
3. Confirma TShark disponível. cryptography pode estar false para esta demonstração de código/JSON/TLS.
4. Executa uma análise do desafio e guarda-a no histórico como Challenge baseline. Confirma 28 analisados, 619 nos cartões, 955 ofertas e 9 por rever. Se divergir, consulta cobertura, versão e ferramentas antes de usar os números dos slides.
5. Confirma os oito ficheiros em Preparacao/FICHEIROS_NOVOS: 9 observações, 2 críticas, 2 médias, 4 resilientes, 1 por rever, índice 37.5.
6. Abre 01_aes128.py num editor de texto, com token_bytes(16), e abre 04_aes_desconhecido.py. Deixa-os prontos sem executar nenhum deles.
7. Deixa os relatórios offline do desafio e dos oito exemplos acessíveis. O pacote inclui cópias chamadas QuantumTrace_Challenge_Offline.html e QuantumTrace_Examples_Offline.html.
8. Abre o PowerPoint no teu PC, confirma aspeto e notas. Testa Alt+Tab para a app e para o editor. Escolhe um zoom que permita ler a evidência no ecrã de apresentação.
9. Não limpes o histórico imediatamente antes da apresentação. Os resultados de reserva ajudam se houver uma falha ao vivo. Conserva privado o token de sessão que aparece no terminal de arranque.
10. Confirma com a organização a duração, formato e canal de entrega. Ainda não foi feita qualquer submissão por este pacote.

## 3. Versão principal: cinco minutos

### 0:00-0:25. Slide 1: QuantumTrace

Ação: Mostra a capa. Olha para o júri. Apresenta o problema em linguagem simples.

Fala:

Hi, I'm Pedro from Hidden Signal. Before planning a post-quantum migration, an organisation needs to know where it uses cryptography. QuantumTrace inspects source code, cloud configurations and TLS captures, and connects each finding to evidence that a reviewer can check.

### 0:25-1:00. Slide 2: Cryptographic evidence

Ação: Mostra as três linhas da tabela. O objetivo é explicar entradas e grau de evidência, sem enumerar todos os módulos.

Fala:

The engine recognises supported calls, configuration fields and handshake identifiers. It normalises these into a cryptographic inventory, then applies explicit assessment rules. Code and configuration show declarations or static calls. A capture can show selected mechanisms. Keeping those evidence types separate helps us explain what each result actually proves.

### 1:00-1:35. Slide 3: Results on the supplied data

Ação: Aponta primeiro para 1574, 619 e 955. O gráfico inclui os nove casos por rever, mas esses nove ficam fora da média do índice.

Fala:

On the supplied synthetic data, the report contains 1,574 observations from 28 analysed files. The cards show 619 observations. Another 955 are TLS client offers, so they stay outside the index. The current index is 61.5. These numbers describe primitive occurrences. Repeated components affect the score, and it is not an attack probability.

### 1:35-2:10. Slide 4 e app: evidência do desafio

Ação: Mostra o slide 4 brevemente e muda para a app. Carrega em Analyse challenge data, com o nome Challenge live. Se a análise da captura demorar, abre Challenge baseline e identifica-a como análise anterior. Pesquisa acm_certificates.json e filtra Critical para mostrar uma declaração RSA. Carrega em Inspect evidence e destaca Rule e Next step. Fecha o diálogo. Na área Priorities by file or resource, pesquisa acm_certificates.json e mostra a ação baseada em configuração. Limpa a pesquisa antes de mudar de análise.

Fala:

I'm scanning the bundled challenge files again. The priority summary groups evidence and next steps by file or resource. Each result keeps a source location and a rule. This RSA declaration is critical because the classical public-key component is exposed to Shor.

### 2:10-2:50. App: dados novos e incerteza

Ação: Carrega em Choose folder e escolhe apenas Preparacao/FICHEIROS_NOVOS, ou Choose files e seleciona os oito. Nome: Extra examples. Carrega em Analyse selection. Mostra o total nove e pesquisa 04_aes_desconhecido.py. Abre Inspect evidence. Mostra Missing information e Next step. Fecha o diálogo.

Fala:

These eight additional files are our own synthetic examples. They produce nine observations. AESGCM tells us the cipher family, but this function does not tell us the key size. The tool asks us to establish it.

### 2:50-3:45. App e editor: alteração de um parâmetro

Ação: Choose files: seleciona só 01_aes128.py. Nome: AES 128 baseline. Analyse selection. Mostra AES, 128 bits, Medium. No editor troca token_bytes(16) por token_bytes(32) e guarda. Volta à app, escolhe novamente o mesmo ficheiro e faz outra Analyse selection, com nome AES 256 change. Mostra AES, 256 bits, Resilient. O navegador pode conservar o conteúdo de uma seleção antiga; por isso tens de voltar a selecionar.

Fala:

Now I analyse just this file. Sixteen bytes means AES-128. I change sixteen to thirty-two, save and select the file again. The new analysis records AES-256. That changes the primitive's challenge tier. It does not certify the application.

### 3:45-4:10. App: entrega do resultado

Ação: Mostra Download JSON. Se o tempo permitir, descarrega uma vez e mostra os campos schema, policy e findings no editor. Também existe Download report para HTML offline. A comparação automática é opcional; não gastes o tempo a procurar no histórico.

Fala:

We can export the evidence as JSON, or keep an offline report. History lets us inspect previous runs.

### 4:10-5:00. Slide 5: Evidence for migration decisions

Ação: Volta ao PowerPoint. Resume a verificação e o limite da precisão. Fecha com a utilidade concreta. Não avances para os slides de apoio durante a fala principal.

Fala:

Eighty-six automated tests passed, including checks against manual expectations for all 24 supplied source files. The engine also keeps unresolved cases visible. These checks support specific behaviours. We do not yet have independent production accuracy measurements. The new summary groups next steps by file or resource and considers the evidence state. Business context still needs review. Next steps are broader detection, independent evaluation and validated CycloneDX export. QuantumTrace gives reviewers a traceable starting point for migration decisions. Thank you.

Depois da demonstração, restaura token_bytes(16) e guarda o 01. Caso contrário, a próxima validação dos oito exemplos deixa de coincidir com as expectativas originais.

Na alteração 16 para 32, a comparação pode mostrar uma observação removida e outra adicionada porque o tamanho faz parte da identidade. Compara apenas as duas análises do mesmo ficheiro. Comparar o lote de oito com um ficheiro isolado não demonstra uma melhoria de segurança. O delta do índice pode ficar indisponível por terem mudado os inputs.

## 4. Versão curta: três minutos

Mantém os cinco slides, encurta a fala e a demo. Usa o resultado do desafio já guardado. Demonstra o ficheiro novo ao vivo. Omite a análise do lote de oito e a navegação de sessões TLS, mantendo a explicação de incerteza no slide 4. Se ainda houver tempo, abre o caso 04 já guardado.

### 0:00-0:20. Slide 1

Fala:

Hi, I'm Pedro from Hidden Signal. QuantumTrace helps an organisation find the cryptography it needs to review before a post-quantum migration. It connects source code, cloud configuration and TLS evidence in one inventory.

### 0:20-0:40. Slide 2

Fala:

The engine uses explicit rules. It distinguishes a configured mechanism, a static call, an offered option and a selected TLS mechanism. Each finding keeps its source and assessment rule.

### 0:40-1:05. Slide 3 e relatório guardado

Ação: Mostra os números e, se a troca for rápida, abre uma evidência RSA do Challenge baseline. Identifica esse resultado como previamente gerado.

Fala:

The saved challenge report contains 1,574 observations from 28 analysed files. The cards contain 619. Another 955 are client offers, which stay outside the index. The counts refer to primitive occurrences, and the index is a project heuristic.

### 1:05-2:20. Slide 4 e alteração AES

Ação: Analisa só 01, muda 16 para 32, guarda, seleciona novamente e analisa. Mantém o editor aberto antes de começar. Se a app falhar, usa os resultados de reserva, indicando que não são uma análise ao vivo.

Fala:

This new file asks for a sixteen-byte key. The engine identifies AES-128. I change it to thirty-two bytes, save, select it again and run a new analysis. The evidence now records AES-256, which changes the primitive's challenge tier. When the key size is missing, the tool keeps Needs review and states what information is required. The application code is inspected without execution.

### 2:20-3:00. Slide 5

Fala:

Eighty-six automated tests passed, including manual expectations for all 24 supplied source files. This checks specific behaviour, rather than independent production accuracy. Reports are exportable as JSON and offline HTML. Broader detection, validated CycloneDX output and independent evaluation and enterprise context are the next steps. The aim is an inventory whose decisions a reviewer can inspect. Thank you.

## 5. Alternativa se uma ação falhar

| Situação | Ação | Frase em inglês |
| --- | --- | --- |
| Captura demora | Abre Challenge baseline | I will use the previously generated challenge report so we can inspect the evidence. |
| App deixa de responder | Abre QuantumTrace_Challenge_Offline.html | This is an offline report from an earlier run on the same supplied files. It keeps the evidence and assessment details. |
| Upload dos oito demora | Abre QuantumTrace_Examples_Offline.html | These are the saved results for our eight additional synthetic examples. |
| Mudança AES não aparece | Confirma Guardar e volta a selecionar o ficheiro | I need to select the saved file again so the app reads its updated contents. |
| Ainda falha após uma tentativa | Usa o slide 4 e os relatórios de reserva | I will show the saved result and explain the parameter change. I am not claiming a successful live rerun. |
| Números diferem dos slides | Consulta cobertura e versão, não escondas | This run has different coverage or inputs. The slide numbers belong to the supplied baseline report. |

Não percas mais de dez segundos a repetir uma ação falhada. Passa para a reserva, identifica-a e continua a explicar o resultado. Não prometas uma gravação neste pacote: se quiseres uma reserva em vídeo, grava o percurso no teu PC depois do ensaio.

## 6. Perguntas prováveis e respostas em inglês

### What did you build yourself, and how did you use AI?

I developed the prototype with AI assistance for implementation, tests and documentation. The supplied dataset remains unchanged. I selected the workflow, tested it on my computer and worked through the evidence and limitations. The runtime engine uses explicit rules. It does not ask an LLM to assign the classifications.

### What do the new priorities mean?

They group observations by source file, AWS resource or TLS session and show evidence, a reason and a next step. Selected classical mechanisms are reviewed before configured or static ones. Offers remain inventory-only. Hybrid groups receive construction review. This is technical inspection guidance; business impact and confidentiality lifetime are not known.

### How do you know the results are reliable?

Each finding keeps a source location, a file hash, the detector and the assessment rule. Eighty-six automated tests passed, with manual expectations for specific supplied examples and negative cases. These checks support specific behaviours. We do not have complete official labels or an independent production accuracy estimate.

### Does 98.5% mean accuracy?

No. It is classification coverage: 610 of 619 non-offered observations received a tier. It does not measure all crypto occurrences the detector might miss, or whether every classification is correct. Detection accuracy needs a separately labelled evaluation set.

### How exactly do you calculate 37.5?

Two critical observations contribute 200, two medium contribute 100, and four resilient contribute zero. The total is 300 divided by eight rated observations, giving 37.5. The ninth observation needs review and stays outside both the sum and the denominator. These weights are our project heuristic.

### Why do offered mechanisms stay outside the index?

A ClientHello offers options. It does not prove that the server selected any particular option. We keep those offers in the inventory for inspection, but do not count them as selected mechanisms. Configuration and static calls also keep their own evidence labels.

### Does critical mean this is already broken today?

It means a classical public-key component falls in the challenge's Shor-exposure tier for a sufficiently capable quantum computer. The report is not evidence of a current practical quantum break. Classical warnings, such as a small RSA modulus, are separate concerns.

### Why is AES-128 medium?

That tier follows the challenge brief. It does not claim a practical attack today. NIST discusses important limits on the practical advantage of Grover's algorithm. We keep modes, nonces, key management and the surrounding public-key mechanisms separate.

### Are your hash rules official NIST categories?

No. They are our documented policy extension. The ideal query models use n/3 for collisions and n/2 for preimages, against a project target of 128 bits. Those exponents do not estimate attack time or define NIST security categories. We record the context and the policy version.

### Why does HMAC or PBKDF2 still need review?

The digest or output size does not establish the entropy of the secret key or password. We show the parameters the detector can establish and the information that still needs review. A 256-bit PBKDF2 output does not mean a password has 256 bits of entropy.

### What about the AES case with unknown size?

We identify AESGCM through its imported API. The function receives a parameter called chave, but this file has no caller or key origin that establishes its length. The next step is to inspect key generation, configuration or callers. We do not infer AES-256 from the name AESGCM.

### Does a critical X25519 component mean the hybrid is broken?

No. The inventory records the classical and PQC components separately. A classical component's tier does not determine the security of the combined hybrid mechanism. That needs construction, protocol and implementation analysis. We observed seven selected hybrid groups in this capture.

### Can I upload a real project?

You can select a folder within the local upload limits. The engine scans supported Python, Java, Go, JSON, TLS captures and optional public certificate formats. It skips some generated directories and reports unsupported or incomplete files. Complex wrappers, unknown libraries and cross-module data flow can remain missed or unresolved.

### Do uploaded files run?

Source code is parsed rather than executed. TShark reads a local capture if available. The app removes temporary uploaded inputs after analysis and stores generated reports in SQLite. It is a local prototype, and not a production hostile-file sandbox.

### Do you use a JSON API and a database?

Yes. The browser calls a local JSON API for scans, jobs, history, export and comparison. SQLite stores reports. These components use the same deterministic core. They do not require an AI agent or a paid external service.

### Is the CBOM CycloneDX?

The output is a custom cryptographic inventory with schema quantumtrace.inventory/1.0. The brief allows JSON, which is the option implemented here. A validated CycloneDX exporter remains future work. Dependency and library inventory also need broader coverage.

### Why implement parts of all four vectors?

Code, configuration and network adapters provide evidence. The common inventory lets one policy engine and report cover those inputs. The prototype addresses parts of all four vectors, with explicit limits. It does not claim complete binary discovery or full protocol certification.

### What does the user do after seeing a critical finding?

The evidence dialog includes a next step. For classical public-key crypto, it recommends a migration plan appropriate to the role, with key establishment and signatures treated separately. The user must review the surrounding system and deployment constraints. The app does not automatically replace the code.

### How does comparison work?

It compares observations by source, location, algorithm, parameters and relevant context. Identical inputs should keep identical observations. Changing AES key size can appear as one removed and one added observation. Removed means no longer observed, rather than proof of remediation.

### What would you improve next?

I would expand supported patterns and dependency discovery, validate against independently labelled projects, add a schema-validated CycloneDX export, and connect findings to assets and business context. Asset importance and confidentiality lifetime would make migration priorities more useful than counting primitive occurrences alone.

### Is the displayed 127.0.0.1 address my public IP?

It is the loopback address of this computer. The app binds locally. A separate session token authorises API requests. Offline HTML exports open without the server, while external source-documentation links need internet access.

## 7. Slides de apoio durante perguntas

Slide 6, Primitive exposure index: usa-o para explicar 37.5, 61.5 e os pesos. Slide 7, Assessment rules: usa-o para distinguir o enunciado da extensão de hashes. Slide 8, TLS offers and hybrid groups: usa-o para explicar offered, selected e a análise por componentes.

Os três ficam ocultos no percurso principal. No PowerPoint, usa a navegação do modo de apresentação para abrir um slide oculto quando for necessário, ou torna-o visível antes do ensaio. Não dependas de um atalho que ainda não testaste no teu PC.

## 8. Um ensaio que te prepara para perguntas

1. Explica o percurso app.js, app.py, inventory.py, scanners.py, policy.py e report.py sem ler.
2. Justifica uma evidência RSA no campo JSON e uma chamada AES no código.
3. Faz a conta de 37.5 e explica por que são oito no denominador, apesar de nove observações.
4. Explica o 04 por rever e o 05 com zero observações. São dois resultados diferentes.
5. Faz um ensaio de cinco minutos com as ações reais. Depois faz outro de três minutos.
6. No último ensaio, usa o PC, o navegador e o PowerPoint da apresentação. Confirma que as linhas e diálogos são legíveis à distância.

Uma resposta honesta para uma pergunta fora do teu conhecimento:

I have not validated that case yet. This prototype supports the documented patterns, and I would keep that conclusion unresolved until we inspect the evidence and the relevant construction.

## 9. Referências do roteiro

Os resultados vêm de reports/report.json, Preparacao/resultados/report.json e VALIDATION.md da versão 0.3.3. As expectativas adicionais estão em Preparacao/resultados_esperados.json. Os dados do desafio são do snapshot 39e8f18dcfb5edc66eda0f47bb44884aa7db5c9c do repositório https://github.com/joaoalves3901/JunctionX-QuantumTrace.

As notas dos slides contêm as fontes relevantes. Política e limites: POLICY.md. Nuance prática sobre Grover: https://csrc.nist.gov/projects/post-quantum-cryptography/faqs. Norma ML-KEM: https://csrc.nist.gov/pubs/fips/203/final. Os pesos do índice e os níveis adicionais de hashes pertencem à política do projeto.
