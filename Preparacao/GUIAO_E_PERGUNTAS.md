# Hidden Signal - guião provisório

Duração de referência: cerca de dois minutos, a ajustar à duração e língua que a organização confirmar. Os números abaixo correspondem ao conjunto fornecido, analisado com a versão 0.3 e TShark disponível. Confirma-os no teu PC antes de os apresentar. Não apresentes os exemplos novos deste kit como dados fornecidos pelos organizadores.

## Português: fala e ação no ecrã

**0:00-0:20 - O problema.**

"Antes de migrar para criptografia pós-quântica, uma organização precisa de saber onde usa criptografia. Essa informação está dispersa por código, configurações e tráfego de rede. O QuantumTrace reúne essas fontes num inventário com evidência verificável."

**0:20-0:40 - O resultado. Abre a análise do desafio.**

"Neste conjunto sintético fornecido, analisámos 28 ficheiros e encontrámos 1574 observações. Destas, 955 são opções oferecidas pelos clientes TLS; as restantes 619 aparecem nos cartões. São ocorrências de mecanismos, não 1574 vulnerabilidades únicas."

**0:40-1:05 - A confiança. Pesquisa RSA e abre uma evidência.**

"Cada resultado mostra o algoritmo, os parâmetros identificados, a origem e a regra de classificação. Aqui temos uma componente RSA classificada como crítica pela exposição a Shor. O utilizador pode verificar a linha ou o campo de origem e consultar o próximo passo. Não precisa de aceitar uma resposta sem justificação."

**1:05-1:25 - Uma análise nova. Usa a alteração AES ensaiada.**

"Podemos receber ficheiros novos. Neste exemplo, a chave tem 16 bytes e o programa identifica AES-128. Ao mudar para 32 bytes e analisar novamente, identifica AES-256. É a política do desafio aplicada ao parâmetro observado; não é uma certificação da aplicação inteira."

**1:25-1:45 - Rede e limites. Mostra uma sessão híbrida e um caso por rever.**

"Na captura distinguimos opções oferecidas e mecanismos selecionados. Identificámos 97 pares de hello e sete grupos híbridos selecionados. Também conservamos os casos por rever: quando falta informação, o programa explica o que é necessário em vez de declarar segurança."

**1:45-2:00 - Utilidade. Mostra a exportação.**

"O inventário pode ser exportado em JSON e consultado num relatório offline. A aplicação local guarda análises e permite comparações. A classificação usa regras explícitas, sem uma API paga, para apoiar um plano de migração com resultados que podem ser inspecionados."

Se a análise ao vivo ocupar demasiado tempo, encurta a parte da rede ou usa a análise já guardada para os dados do desafio. O ficheiro novo continua a ser analisado ao vivo. O relatório offline é a alternativa de reserva; identifica-o como um resultado anteriormente gerado.

## English: optional spoken version

"Before moving to post-quantum cryptography, an organisation needs to know where it uses cryptography. That information is spread across source code, configuration and network traffic. QuantumTrace brings those inputs into an inventory with inspectable evidence.

On the supplied synthetic dataset, we analysed 28 files and recorded 1,574 observations. Of these, 955 are TLS client offers; the remaining 619 appear in the assessment cards. These are mechanism occurrences, not unique vulnerabilities.

Each finding records the algorithm, identified parameters, source location and assessment rule. This RSA component is critical under the challenge policy because of its exposure to Shor's algorithm. The user can inspect the original location and the suggested next step.

We also accept new files. This example uses a 16-byte key, which is identified as AES-128. After changing it to 32 bytes and analysing it again, the inventory records AES-256. This demonstrates the challenge's primitive-level policy, not certification of the entire application.

In the capture, we distinguish offered options from selected mechanisms. We recorded 97 hello pairs, including seven selected hybrid groups. Missing information stays in a review queue with an explanation of what is needed.

The inventory can be exported as JSON or viewed in an offline report. The local app stores analyses and compares them. Explicit rules and traceable evidence make the results inspectable and help users plan a migration. The core requires no paid API."

## Perguntas prováveis do júri

**Como sabem que os resultados são fiáveis?**

"Os resultados ligam-se às linhas, campos JSON ou pacotes identificados. Temos 86 testes automatizados anteriores, com expectativas específicas para os dados fornecidos, e este kit acrescenta oito exemplos novos com expectativas manuais. Isso valida comportamentos concretos; ainda não temos uma medição independente de precisão geral."

**O que é o índice 61,5?**

"É uma média de observações classificadas: crítico vale 100, médio 50 e resiliente 0. Casos por rever e opções apenas oferecidas ficam fora. No conjunto atual, a conta é `(238 x 100 + 274 x 50) / 610`. É um indicador da composição do inventário, influenciado por repetições, não uma probabilidade de ataque nem um modelo completo de risco empresarial."

**Porque classificam AES-128 como médio se continua a ser usado?**

"Seguimos a categoria pedida pelo desafio. Não afirmamos que exista um ataque quântico prático atual contra esta utilização. A vantagem teórica de Grover e o custo de um ataque real são questões diferentes."

**E as regras de hashes?**

"O enunciado não detalha todos os hashes e contextos. Acrescentámos uma extensão explícita com um alvo teórico e as suas hipóteses. O modelo não corresponde a categorias NIST nem estima o tempo de um ataque real. Esta extensão merece validação adicional e pode ser revista; os relatórios guardam a versão da política."

**Porque há casos por rever?**

"Reconhecer HMAC ou PBKDF2 não nos revela automaticamente a entropia do segredo ou da palavra-passe. A app mostra os parâmetros conhecidos e a informação que falta. Há também uma lacuna explícita na regra para o hash dentro de RSA-OAEP. Não usamos uma classificação positiva para esconder essa incerteza."

**Como recebem dados novos?**

"O utilizador escolhe ficheiros na aplicação local. A API recebe-os, o scanner inspeciona os formatos e padrões suportados e cria um relatório. Os ficheiros brutos são temporários; o histórico SQLite guarda os relatórios. Código de entrada não é executado. Formatos ou padrões desconhecidos têm limites, que devem ser consultados na cobertura."

**Porque não usar um agente de IA?**

"Usámos assistência de IA no desenvolvimento. Na análise, as decisões desta versão vêm de regras inspecionáveis. Uma futura componente de IA poderia ajudar a investigar código mais complexo, sujeita a validação, mas a rastreabilidade deve continuar disponível."

**O vosso JSON é CycloneDX?**

"É um inventário CBOM num esquema próprio, permitido pela opção JSON do desafio. Ainda não temos exportação CycloneDX validada. Essa é uma extensão futura concreta."

**Um grupo híbrido com X25519 é crítico?**

"O inventário regista separadamente os componentes clássicos e PQC. X25519 recebe a classificação da componente clássica; isso não demonstra que o mecanismo híbrido combinado está quebrado. Uma avaliação do protocolo completo exige contexto adicional."

**O que falta para uma utilização empresarial?**

"Mais padrões e formatos, testes independentes, integração com sistemas reais, normalização adicional do CBOM e prioridades baseadas em recursos, criticidade e tempo de confidencialidade. Esta versão é um protótipo local validado em exemplos específicos."

## Estrutura de cinco slides

1. Problema: onde está a criptografia que teremos de migrar?
2. Funcionamento: capturas TLS, código e configurações; inventário; regras; evidências.
3. Uma descoberta verificável: imagem real do teu PC com localização e próximo passo.
4. Validação e limites: verificações concretas, casos por rever e âmbito do índice.
5. Utilidade e próximos passos: exportação, prioridades de migração e extensões propostas.

Captura as imagens depois de confirmar a app no computador da apresentação. Não uses imagens de resultados inventados. Confirma o tempo permitido antes de fechar o número de slides.

## Ensaio e alternativa de reserva

- Faz três ensaios cronometrados: o primeiro para encontrar dificuldades, o segundo sem consultar notas e o terceiro no computador da apresentação.
- Prepara uma análise do desafio no histórico e o relatório offline.
- Grava uma demonstração de 60 a 90 segundos no teu PC. Não depende de uma gravação criada por este kit.
- No ensaio final, confirma zoom, idioma, janela de evidência, ficheiro novo, exportação e terminal aberto.
- Se surgir uma pergunta fora do âmbito, explica o que foi verificado e o que ainda falta. Não improvises uma garantia de segurança.

Fontes: enunciado fornecido, documentação e resultados do QuantumTrace 0.3; NIST PQC FAQ (limites práticos de Grover): https://csrc.nist.gov/projects/post-quantum-cryptography/faqs.
