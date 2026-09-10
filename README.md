# Telemetria de ferramentas

Esta integração mede, por sete dias, o uso e o custo operacional das ferramentas
locais. O coletor é `tool_telemetry.py`; as unidades systemd somente o chamam e
não apagam dados.

Cada amostra também registra a própria sobrecarga do coletor: duração, CPU,
RSS máximo e tamanho dos arquivos de estado/eventos. Isso permite avaliar o
custo da medição sem persistir comandos ou conteúdo.

As métricas Codex/Claude cobrem todas as sessões concorrentes da máquina. O
parser v2 usa os eventos concluídos `CommandExecution` e `McpToolCall` como
fontes autoritativas, ignora corpos de heredoc e não transforma nomes apenas
citados em chamadas. O relatório exclui das métricas de invocação qualquer
amostra anterior a essa versão, mas preserva seus dados agregados de processo,
probes e sobrecarga. O matcher de processos v2 só aceita identidade de
executável ou de um wrapper conhecido; CPU/RSS de eventos sem essa versão são
preservados, mas excluídos do custo observado no relatório final.

## Resultados do h5i

A atribuição v2 separa chamadas diretas do h5i de `h5i capture run -- ...`.
Capturas mantêm o uso contabilizado, mas o resultado próprio do h5i fica
`desconhecido`: saída zero/não zero da execução capturada tem contadores
separados. Uma saída não zero pode vir do comando filho ou do capturador;
sem evidência específica, não se presume a causa. A duração da captura não
entra na latência própria do h5i.

Relatórios novos apresentam resultados antigos do h5i como desconhecidos e
explicitam a quantidade de erros legados sem atribuição. Eventos e relatórios
já emitidos permanecem preservados. Chamadas pendentes antigas também não
recebem atribuição causal retroativa. Somente indicadores e contagens são
persistidos, nunca comandos ou saídas.

## Operação

1. Instale as unidades sem criar estado ou janela: `./install.sh install`.
2. Inicie a medição e exclua cada sessão dedicada à própria auditoria:
   `./install.sh start --exclude-session /caminho/absoluto/sessão.jsonl`.
3. Consulte execução e dados: `./install.sh status`; veja o journal com `./install.sh logs`.
4. Para a medição sem apagar estado nem relatórios: `./install.sh stop`.

`--exclude-session` é repetível. O instalador aplica todas as exclusões depois
de criar ou carregar o estado e antes de instalar ou ativar os timers, sem uma
corrida com a primeira amostra. Uma sessão dedicada à implementação ou auditoria
do próprio coletor deve ser informada nesse comando. Somente o SHA-256 do caminho
é persistido; o arquivo, seu caminho e seu conteúdo não são copiados.

Para descartar uma janela enviesada sem apagar seus dados, execute `stop` e use
`start --new-run --state-dir /caminho/absoluto/novo` junto das exclusões. O novo
diretório deve estar sem `state.json`; os timers precisam estar parados e
desabilitados. O instalador preserva o estado anterior, cria sete dias completos
no novo diretório e substitui apenas as unidades desativadas.
Para consultar essa execução, repita o mesmo diretório:
`./install.sh status --state-dir /caminho/absoluto/novo`; sem essa opção, o
comando consulta o diretório padrão preservado.
O coletor continua avançando o cursor JSONL dessa sessão, sem contabilizar suas
chamadas nem atividade. Essa exclusão não se aplica ao histórico zsh global,
que não contém vínculo confiável com uma sessão; comandos interativos ali
registrados continuam sendo contados. Os serviços não interativos do coletor
não escrevem nesse histórico.

Use `--dry-run` para conferir os comandos sem alterar arquivos ou unidades. Por
padrão, o estado privado fica em `~/.local/state/tool-telemetry` e as unidades em
`~/.config/systemd/user`. Os dois caminhos podem ser substituídos com
`--state-dir` e `--unit-dir`; `--workspace` seleciona a raiz monitorada. O
runtime privado fica em `~/.local/share/tool-telemetry` por padrão e pode ser
substituído por `--runtime-dir`.

Durante `install`, `tool_telemetry.py` e este README são copiados para o runtime
com arquivos `0600` e diretório `0700`; cada arquivo é publicado por troca
atômica. As unidades executam e documentam somente essa cópia, portanto uma
troca de branch ou limpeza do checkout não interrompe uma janela já instalada.
Um `install` durante janela ativa atualiza runtime e unidades, mas preserva
state, janela e timers. `--dry-run` apenas mostra essas ações e não escreve.

O temporizador de amostra executa após 30 segundos e, depois, a cada cinco
minutos. A primeira coleta usa `sample --force-deep`; as seguintes usam `sample`. Um
segundo temporizador recebe, no primeiro `start`, o `window_end` real criado no
`state.json` pelo coletor; esse mesmo instante UTC absoluto vai para
`OnCalendar=`. Sem atraso aleatório e com precisão de um segundo, ele dispara
`finalize` nesse instante. Um `start` posterior só retoma quando
state e timer existem e têm o mesmo início/fim; qualquer ausência, divergência
ou prazo vencido falha fechado, sem criar outra execução. Reiniciar o host ou o
gerenciador systemd do usuário não reinicia os sete dias. O serviço final desativa o
temporizador recorrente e deve gerar
`docs/telemetria-ferramentas-codebase-contexto-2026-09-08.md`.

Se a finalização falhar, a unidade tenta novamente após cinco minutos. O systemd
limita as partidas a 12 dentro de uma janela de uma hora. O coletor torna a
finalização idempotente: o mesmo arquivo
de relatório é regravado atomicamente e o evento final só é registrado uma vez.
O temporizador de amostra só é desativado pelo `ExecStartPost` após êxito; durante
as falhas e tentativas ele permanece ativo. Ao atingir o limite, a unidade entra
em `start-limit-hit` e exige `systemctl --user reset-failed
tool-telemetry-finalize.service` seguido de `systemctl --user start
tool-telemetry-finalize.service`, sem desligar a amostragem.

As unidades usam `UMask=0077`, limites de CPU, memória e tempo, e restringem a
escrita ao diretório de estado e a `docs/`. Os registros ficam exclusivamente no
journal do systemd do usuário. Elas recebem somente um `PATH` absoluto,
sanitizado e independente da sessão interativa: `~/.local/bin`, pnpm, Bun,
Linuxbrew, diretórios atuais de Node, `sc` e `rg`, além de `/usr/local/bin`,
`/usr/bin` e `/bin`. O instalador enumera o ambiente atual do gerenciador e
renderiza `UnsetEnvironment=` para descartar cada variável herdada, exceto
`HOME`, `PATH`, `STATE_DIR`, `WORKSPACE_DIR`, `PYTHONUNBUFFERED`,
`XDG_RUNTIME_DIR` e os quatro limites de threads BLAS; valores de segredos nunca
são gravados na unidade.
`LimitCORE=0` impede dumps de memória. `MemoryDenyWriteExecute` não é usado,
pois quebraria CLIs com JIT, como Node e ferramentas JavaScript.
`PrivateNetwork=yes` isola cada unidade em um namespace de rede privado, sem
depender do firewall de IP que não é aplicado a unidades `systemd --user`; a
integração não renova OAuth.
Bibliotecas BLAS ficam limitadas a uma thread por variável de ambiente, para
respeitar `TasksMax=32` quando uma probe Python roda como subprocesso.

## Intervenção durante a janela

Em `2026-09-04T23:32:00Z`, a configuração foi endurecida sem reiniciar a
janela: o isolamento de rede passou a usar `PrivateNetwork=yes`, a probe do
SegundoCerebro passou a ser local (`sc --help`) e o matcher de processos passou
à versão 2. O relatório final deve separar os agregados anteriores e
posteriores a essa intervenção; CPU/RSS anteriores ao matcher v2 são excluídos
do custo de processo, embora seus eventos permaneçam no estado.

O matcher v2 reconhece executáveis por nome exato. Serviços iniciados por
Python, Node, Bun ou npm só são atribuídos quando o entrypoint exato está sob a
raiz conhecida da ferramenta: SegundoCerebro, codeweb, context-mode,
claude-mem/Chroma, codex-security ou Headroom. `rg` e `ast-grep` exigem ainda o
realpath do binário devolvido por `which`. Isso evita tanto rótulos como
`systemd-inhibit --who codex` quanto preferências do earlyoom, sem omitir os
MCPs residentes legítimos.

O módulo Python `headroom.cli` é uma exceção explícita e exata para o proxy do
Headroom; módulos parecidos não contam. `chroma-mcp` é reconhecido apenas como
executável exato ou comando lançado por `uv`, pois sua instalação pode ficar
fora da árvore do claude-mem.

## Limites operacionais

O usuário precisa ter um gerenciador `systemd --user` acessível. Como o timer
final usa `OnCalendar=` absoluto e `Persistent=true`, caso o host esteja
desligado no instante agendado, a finalização pendente ocorre na próxima sessão
sem reiniciar a janela. O comando `stop` desativa os dois temporizadores e
mantém todos os dados para inspeção ou reinício posterior.
