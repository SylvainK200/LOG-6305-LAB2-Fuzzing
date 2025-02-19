from poly_fuzzer.common.abstract_grammar import AbstractGrammar
import re, random

class HtmlGrammar(AbstractGrammar):
    def __init__(self, gram:dict):
        AbstractGrammar.__init__(self, gram)
        self.START_SYMBOL = "-start>"
        self.RE_NONTERMINAL = re.compile(r"(-[^>< ]*>)")

    def generate_input(
        self,
        start_symbol="<start>",
        max_nonterminals: int = 10,
        max_expansion_trials: int = 100,
        log: bool = False,
    ) -> str:
        """Produce a string from `grammar`.
        `start_symbol`: use a start symbol other than `<start>` (default).
        `max_nonterminals`: the maximum number of nonterminals
            still left for expansion
        `max_expansion_trials`: maximum # of attempts to produce a string
        `log`: print expansion progress if True"""

        term = start_symbol
        expansion_trials = 0
        grammar = self.gram
        while len(self.nonterminals(term)) > 0:
            symbol_to_expand = random.choice(self.nonterminals(term))
            expansions = grammar[symbol_to_expand]
            expansion = random.choice(expansions)
            # In later chapters, we allow expansions to be tuples,
            # with the expansion being the first element
            if isinstance(expansion, tuple):
                expansion = expansion[0]

            new_term = term.replace(symbol_to_expand, expansion)
            if len(self.nonterminals(new_term)) < max_nonterminals:
                term = new_term
                if log:
                    print("%-40s" % (symbol_to_expand + " -> " + expansion), term)
                expansion_trials = 0
            else:
                expansion_trials += 1
                if expansion_trials >= max_expansion_trials:
                    print("Cannot expand " + repr(term))
        return term


