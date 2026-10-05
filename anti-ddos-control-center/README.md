# Anti-DDoS Control Center

Central **defensiva** de proteção contra tráfego abusivo (rate limiting, bloqueio de IPs,
whitelist e logs). Somente biblioteca padrão do Python 3.8+. Funciona em Termux/Linux/Windows.

## Executar

    python3 anti_ddos.py              # abre a central
    python3 anti_ddos.py --no-color   # sem cores ANSI
    python3 -m unittest discover -v   # testes

Dados em `~/.anti_ddos_center/` (`config.json`, `events.log`). Para outra pasta use
`--data-dir PASTA` ou a variável `ANTI_DDOS_HOME`.

## Camadas

    anti_ddos.py              entry point
    anti_ddos_center/
        validation.py         validação de entradas (IP, inteiros)
        config.py             configuração persistente (config.json)
        logger.py             events.log
        ip_manager.py         bloqueios e whitelist
        rate_limiter.py       janela deslizante por IP (memória)
        core.py               AntiDDoS: motor que une tudo
        cli.py                interface de terminal

## Integração com o seu servidor/site

    from anti_ddos_center import AntiDDoS

    engine = AntiDDoS()                       # mesma config usada pela CLI

    def on_request(client_ip):
        verdict = engine.check_request(client_ip)
        if not verdict.allowed:
            return 429, {"Retry-After": str(int(verdict.retry_after))}
        ...

Prioridade das decisões: whitelist > proteção desligada > bloqueio permanente >
bloqueio temporário > rate limit. A whitelist nunca é bloqueada.

Observação: atrás de proxy/CDN, passe o IP real do cliente (ex.: cabeçalho
`X-Forwarded-For` de um proxy confiável), não o IP do proxy.
