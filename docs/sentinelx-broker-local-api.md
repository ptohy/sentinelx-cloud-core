# Broker privilegiado via local_api — protótipo

**Sem implantação e sem redução de privilégios.** Esta branch é dependente do broker root do PR #2.

## Arquitetura

O hub SentinelX já oferece a operação `local_api` com JSON-RPC sobre socket Unix. Não é necessário alterar o protocolo para usar essa via. A instância cli-dev atualmente não anuncia `local_api`, pois não há endpoints configurados.

O broker aceita apenas dois métodos JSON-RPC. O método define a operação, sem permitir que parâmetros troquem um efeito por outro:

| Método fixo | Operação permitida |
| --- | --- |
| `tohy.audit.check` | `audit-check` (leitura) |
| `tohy.audit.record` | `audit-record` (auditoria oneshot) |

O único parâmetro aceito é `ticket`: 64 caracteres hexadecimais minúsculos. Argumentos extras, comandos arbitrários, métodos de emissão de tickets e operações não declaradas falham fechados. A emissão continua exclusiva da interface nativa para `root`.

## Exemplo de configuração — NÃO APLICAR

```yaml
local_apis:
  tohy_privileged_broker:
    transport: unix
    protocol: jsonrpc
    path: /run/tohy-sentinelx-privileged-broker/broker.sock
    timeout_s: 8
    actions:
      audit.check:
        method: tohy.audit.check
        params:
          type: object
          required: [ticket]
          additionalProperties: false
          properties:
            ticket: { type: string, pattern: '^[0-9a-f]{64}$' }
      audit.record:
        method: tohy.audit.record
        params:
          type: object
          required: [ticket]
          additionalProperties: false
          properties:
            ticket: { type: string, pattern: '^[0-9a-f]{64}$' }
```

O schema da configuração orienta os clientes, mas a validação de método, ticket e identidade é realizada independentemente pelo broker. O alias `tohy_privileged_broker` deve ser preservado para a redação mais restritiva da auditoria local.

## Sigilo e limites

A auditoria do agente omite **todos os parâmetros** do endpoint `tohy_privileged_broker`, inclusive campos desconhecidos e cópias do ticket com outros nomes. Para outros endpoints local_api, parâmetros nomeados `ticket` também são ocultados. A redação não modifica o payload original.

O ticket ainda transita pelo Hub hospedado. **Não houve verificação de retenção, logs, tracing ou tratamento de segredos no Hub proprietário.** Não transmitir tickets reais de produção por esse caminho até a revisão de privacidade e do modelo de autorização.

Há um segundo bloqueio: o SentinelX da VM104 ainda possui `NOPASSWD: ALL`. Um script arbitrário pode chamar `sudo` fora do broker. Este projeto não restringe privilégios efetivos e não autoriza mudar `/etc/sudoers`, a configuração do agente ou reiniciar serviços.

Os tickets são emitidos apenas por root e consumidos atomicamente uma vez, vinculados à operação, UID/GID, boot e expiração. O consumo não é atômico com o efeito externo; um crash entre os dois pode deixar a operação sem execução.

## Evidência e próximos gates

Testes locais validam conversão JSON-RPC restrita, ocultação de segredos, replay e despacho do `Executor` usando o `local_api` existente e um servidor Unix simulado. O broker root do PR #2 passou em E2E real independente com UID 992/NoNewPrivileges. O canário combinado pelo socket real e Hub hospedado **não está homologado**.

Faltam autoridade de aprovação independente do usuário SentinelX, autorização vinculada à solicitação, auditoria durável, supervisão, migração dos consumidores, revisão do tratamento do ticket pelo Hub e restauração de acesso testada. A migração do sudoers permanece BLOQUEADA.

Os PRs experimentais do handler próprio e do protocolo ampliado não são necessários para esta rota e não devem ser implantados.
