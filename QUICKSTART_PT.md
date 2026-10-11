# QuantumTrace 0.3 — Hidden Signal

1. Descarrega o ZIP, faz botão direito e escolhe **Extrair tudo**. Não abras
   os atalhos dentro do ZIP. Abre a pasta extraída `quantumtrace`.
2. Faz duplo clique em **INICIAR_APP.cmd**. O navegador abre a app local.
   Mantém a janela do terminal aberta; podes minimizá-la. Se o navegador não
   abrir, copia para ele o endereço que aparece no terminal.
3. Carrega em **Analisar dados do desafio**. Para dados novos, usa **Escolher
   ficheiros** ou **Escolher pasta** e depois **Analisar seleção**.
4. Consulta os cartões, os **Casos por rever** e **Ver evidência**. O histórico
   guarda cada análise; escolhe duas para comparar. Descarrega HTML ou JSON
   quando quiseres partilhar o resultado. Há um botão para trocar PT/EN.
5. A pasta **Preparacao** já está incluída, junto de `INICIAR_APP.cmd`.
   Começa por `Preparacao/COMECA_AQUI.md`. Para verificar os oito exemplos
   novos, abre `Preparacao/VALIDAR_EXEMPLOS.cmd`.

Já tendo Python e TShark instalados, não precisas de voltar a instalá-los.
A app, a API JSON e a base de dados SQLite usam apenas o Python incluído na
instalação normal. Não são necessárias contas, chaves de API ou serviços pagos.
Python 3.10 ou mais recente é necessário para executar análises.

A app usa um endereço `127.0.0.1`, acessível neste computador. Fechar o terminal
termina a app; volta a abrir `INICIAR_APP.cmd` para continuar. O histórico fica
em `.quantumtrace/history.sqlite3` dentro da pasta extraída. Abre a mesma pasta
para recuperar o histórico. Para preservar o histórico ao mudar de versão,
copia esse ficheiro com a app fechada; a nova pasta começa com histórico vazio.

## O que significa cada ação

- **Abrir uma análise no histórico:** consulta os resultados guardados, sem
  executar o analisador novamente.
- **Apagar:** remove apenas essa análise do histórico, após confirmação.
- **Limpar histórico:** remove todas as análises guardadas, após confirmação.
  Aguarda a conclusão de qualquer análise em curso. Os ficheiros originais,
  o relatório offline incluído e os relatórios já descarregados mantêm-se.
- **Analisar dados do desafio:** executa uma nova análise da pasta `data` e
  cria uma nova entrada no histórico. Dados e ferramentas iguais costumam
  produzir as mesmas observações.
- **Analisar seleção:** analisa os ficheiros ou a pasta que escolheste, sem
  precisares de substituir a pasta `data`.
- **ABRIR_RELATORIO.cmd:** abre o relatório offline incluído, sem executar
  análise ou precisar de Python. Também podes abrir `reports/report.html`.
- **ANALISAR_DADOS.cmd:** repete a análise de `data` e atualiza
  `reports/report.html` e `reports/report.json`. Este atalho não cria entradas
  no histórico da app.

O total do conjunto fornecido é **1574 observações**, não 1574 ficheiros:
**619 nos cartões + 955 opções TLS oferecidas**. Há 28 ficheiros analisados e
7 ficheiros de metadados fora dos formatos suportados. A tabela começa nas
observações dos cartões; escolhe todas as observações ou apenas ofertas TLS
para consultar as restantes.

Nesta versão, os cartões mostram 238 críticas, 274 intermédias, 98 resilientes
e 9 por rever. O índice é 61,5/100. A mudança de valores face à versão 0.2
reflete as novas regras, não uma alteração dos ficheiros ou uma correção de
vulnerabilidades. Os motivos e as suposições estão visíveis na evidência.

## Dependências opcionais

TShark, instalado com o Wireshark, é necessário para analisar PCAP/PCAPNG.
A app reconhece o PATH e as pastas habituais do Wireshark no Windows. Se faltar,
o código e os JSON são analisados e a captura fica marcada como parcial.
O relatório incluído no ZIP já foi gerado com TShark.

`cryptography: false` não bloqueia a app nem os dados JSON do desafio. Esta
biblioteca é necessária apenas para ler certificados/chaves públicas PEM/DER:

```powershell
py -3 -m pip install "cryptography>=42"
```

Não é necessário instalá-la para os ficheiros atualmente fornecidos.

## Terminal e verificação

A partir da pasta extraída, no Windows:

```powershell
py -3 -m quantumtrace doctor
py -3 -m quantumtrace serve
py -3 run_demo.py
py -3 -m unittest discover -s tests -v
```

No Linux/macOS, usa `python3` em vez de `py -3`. Para outra pasta:

```bash
python3 -m quantumtrace scan /caminho/dos/dados --out reports
```

Os resultados classificam primitivas e observações, sem certificar sistemas.
A evidência estática não prova execução; uma oferta TLS não prova seleção.
Consulta `VALIDATION.md`, `POLICY.md` e `DEMO_PT.md` para a validação, regras
e roteiro da apresentação.

## Atualização 0.3.1

A app guarda o token de arranque na sessão do separador e retira-o da barra de endereço. Podes atualizar o mesmo separador. Os links de documentação do relatório abrem num novo separador. Para analisar um ficheiro de qualquer pasta, usa Escolher ficheiros e depois Analisar seleção; não edites INICIAR_APP.cmd. A pasta Preparacao está agora incluída na posição necessária para o teste adicional encontrar o core.
