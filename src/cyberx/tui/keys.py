"""Key bindings (SPEC §12.3). Extra: c = run one cycle, g = graph, n = network, t = target."""

BINDINGS = {
    "s": "start",
    "p": "pause",
    "r": "resume",
    "x": "stop",
    "c": "cycle",
    "f": "findings",
    "i": "investigations",
    "g": "graph",
    "n": "network",
    "t": "target",
    "w": "world",
    "h": "hypotheses",
    "l": "logs",
    "o": "report",
    "q": "quit",
    "?": "help",
}

HELP_TEXT = (
    "s start   p pause   r resume   x stop   c one cycle\n"
    "f findings   i investigate   g graph   n network   t target   w world   "
    "h hypotheses   l logs   o report   q quit"
)
