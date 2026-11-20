# Broker SentinelX — autorização local sem tickets no Hub

**Status:** protótipo somente no fork; sem merge, deploy, mudanças em `sudoers`, reinício de serviço ou alteração do agente instalado.

## Objetivo e fronteira de confiança

Eliminar o tráfego de *bearer tickets* privilegiados pelo Hub hospedado do SentinelX. O Hub já dispõe de `local_api`; somente o método **read-only** `tohy.audit.status` será configurável para essa integração. A execução acontece exclusivamente mediante comando local emitido por uma identidade `root` confiável na VM104 `codex-dev`, que se conecta ao broker root via socket Unix.

Este protótipo **não** é uma garantia de aprovação humana: a autoridade de aprovação é o controle local de `root`. No ambiente atual, o usuário `sentinelx` mantém `NOPASSWD: ALL`, logo pode elevar a root e contornar o modelo. É proibido interpretar esta etapa como redução de privilégio efetivo.

## Operações disponíveis

| Canal | Ação | Quem pode usar | Efeito |
| --- | --- | --- | --- |
| Socket nativo | `run` / `audit-check` | peer UID 0 | Verificação de auditoria preexistente, sem shell arbitrário |
| Socket nativo | `run` / `audit-record` | peer UID 0 | Registro oneshot de auditoria preexistente |
| JSON-RPC via `local_api` | `tohy.audit.status` | peer `sentinelx` UID 992 / GID 990 | Retorna até 10 recibos não sensíveis; nenhum efeito |

Os métodos anteriores `tohy.audit.check`, `tohy.audit.record`, `tohy.audit.execute` e qualquer tentativa de transportar `ticket` em JSON-RPC são negados. A interface nativa legada de tickets do PR #2 permanece para compatibilidade local, mas não é anunciada ou disponibilizada ao Hub por esta rota. Esta versão substitui a configuração remota anterior do PR #4 e pode ser revisada diretamente contra o broker-base do PR #2.

## Exemplo de configuração futura — NÃO APLICAR

```yaml
local_apis:
  tohy_privileged_broker:
    transport: unix
    protocol: jsonrpc
    path: /run/tohy-sentinelx-privileged-broker/broker.sock
    timeout_s: 8
    actions:
      audit.status:
        method: tohy.audit.status
        description: Consulta somente leitura de recibos locais de auditoria
        params:
          type: object
          additionalProperties: false
          properties: {}
```

A política do agente acima descreve uma única ação sem parâmetros. O broker valida o método e impõe `params={}` independentemente da configuração. Para o endpoint fixo `tohy_privileged_broker`, a auditoria do agente descarta integralmente todos os parâmetros recebidos; portanto, mesmo chamadas inválidas não registram segredos de parâmetros nesse log. Isso não garante que campos fora dos parâmetros, outros endpoints, o Hub ou a infraestrutura de terceiros não mantenham logs.

## Iniciação local e recibos

O cliente administrativo em `security/privileged_broker_admin.py` aceita somente `audit-check` ou `audit-record`, exige UID 0, confirma o host e verifica as permissões e a identidade root do socket via `SO_PEERCRED`. É código-fonte de protótipo, **não é um binário instalado**. Em uma instalação aprovada, precisará de empacotamento e serviço de supervisão próprios.

Cada solicitação local recebe um `request_id` hexadecimal aleatório de 128 bits, sem propriedades de bearer token. O broker insere esse identificador em SQLite root-owned, sob `BEGIN IMMEDIATE`, antes de iniciar a operação fixa. Um mesmo ID nunca executa duas vezes, inclusive depois de falha. O broker registra estados `started_unknown`, `completed` ou `failed`; depois de um reinício, uma execução iniciada mas não confirmada aparece como `unconfirmed_after_restart`. Não há repetição automática.

**Limite crítico de atomicidade:** registrar uma intenção e executar um efeito externo não são uma única transação. Uma falha do broker após o commit e antes do efeito pode deixar a operação não executada com resultado desconhecido. Isso é idempotência de submissão, **não** exatamente uma execução de efeito. Recibos não possuem ainda assinatura, trilha imutável independente, retenção definida ou supervisão de reinício.

## Validação concluída até este checkpoint

- Testes direcionados de tokens legados, autorizações locais, SQLite, execução fixa, falhas, replay, identificação e API de status.
- Despacho `Executor.dispatch(local_api)` exercitado com servidor Unix simulado, sem ticket ou parâmetro de execução.
- Cliente root validado por testes de unidade com identidade e socket simulados. Nenhum efeito privilegiado real foi acionado por este cliente de protótipo.
- A versão original do broker do PR #2 passou anteriormente em E2E real independente por socket com UID 992, mas o **fluxo combinado de execução local + Hub hospedado** ainda não foi homologado.

## Bloqueios obrigatórios antes de qualquer produção

1. Retirar `NOPASSWD: ALL` **somente** depois de mapear e migrar todas as operações privilegiadas existentes, incluindo exec, script_run e fluxos auxiliares, com mecanismo independente de recuperação de acesso.
2. Separar a autoridade de aprovação de uma conta capaz de elevar a root arbitrariamente. Implementar evidência durável de aprovação e recibos de execução auditáveis.
3. Proteger e supervisionar o broker real com systemd, isolamento de socket e recuperação segura sem reinício inesperado ou perda de efeito.
4. Definir política de retenção, backup e restauração da base de recibos, além de cenários de interrupção, reboot e falha de disco.
5. Validar E2E do caminho efetivo de leitura pelo Hub e o teste de não vazamento de dados antes de anunciar `local_api` na instalação ativa.

**Resultado operacional:** nenhuma mudança na VM104 além de arquivos de desenvolvimento e unidades transitórias de teste. Esta etapa não autoriza alterar a política `sudo` ou as permissões do agente.
