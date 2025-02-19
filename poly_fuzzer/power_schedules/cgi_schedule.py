from poly_fuzzer.fuzzers.abstract_fuzzer import AbstractFuzzer
from cgi_decode import cgi_decode
from poly_fuzzer.common.abstract_executor import AbstractExecutor
from poly_fuzzer.common.abstract_seed import AbstractSeed
from poly_fuzzer.fuzzers.mutation_fuzzer import MutationFuzzer
from poly_fuzzer.power_schedules.abstract_power_schedule import AbstractPowerSchedule
from poly_fuzzer.common.abstract_grammar import AbstractGrammar
import string
import random
import numpy as np
class CgiSchedule(AbstractFuzzer):
    def __init__(self, executor,
                 seeds,
                 power_schedule: AbstractPowerSchedule = None,
                 grammar = None,
                 min_mutations: int = 1,
                 max_mutations: int = 10,
                 random_seed  = None
                 ):
        AbstractFuzzer.__init__(self, executor)
        self.current_input = ''
        self.seeds = seeds
        self.seed_index = 0
        self.min_mutations = min_mutations
        self.max_mutations = max_mutations
        self.grammar = grammar
        self.random_seed = random_seed
        self.power_schedule=power_schedule
        self.mutators = [self._delete_random_character, self._replace_random_character, self._insert_random_character]

    def generate_input(self):
        """Mutate the seed to generate input for fuzzing.
                With this function we first use the gien seeds to generate inputs
                and then we mutate the seeds to generate new inputs."""
        if self.seed_index < len(self.seeds):
            # Still seeding
            inp = self.seeds[self.seed_index].data
            self.seed_index += 1
        else:
            # Mutating
            inp = self._create_candidate()

        return inp

    def _update(self, input):
        """Update the fuzzer with the input and its coverage."""
        if len(self.data["coverage"]) > 1:
            if self.data["coverage"][-1] > self.data["coverage"][-2]:
                self.seed_index += 1
                self.seeds.append(AbstractSeed(input))

    def _create_candidate(self):
        seed = np.random.choice(self.seeds)
        grammar_element = ''
        if (self.grammar):
            grammar_element = self.grammar.generate_input()
        # Stacking: Apply multiple mutations to generate the candidate
        if self.power_schedule:
            candidate = self.power_schedule.choose(self.seeds).data
            candidate = grammar_element + candidate
        else:
            candidate = seed.data
        # Apply power schedule to generate the candidate
        #
        trials = random.randint(self.min_mutations, self.max_mutations)
        for i in range(trials):
            candidate = self.mutate(candidate)
        return candidate

    def mutate(self, s):
        """Return s with a random mutation applied"""
        if(self.random_seed):
            random.seed(self.random_seed)
        mutator = random.choice(self.mutators)
        return mutator(s)

    def _delete_random_character(self, s):
        """Returns s with a random character deleted"""
        if(self.random_seed):
            random.seed(self.random_seed)
        if len(s) > 5:
            pos = random.randint(0, len(s) - 1)
            return s[:pos] + s[pos + 1 :]
        else:
            return s

    def _insert_random_character(self, s):
        """Returns s with a random character inserted"""
        if(self.random_seed):
            random.seed(self.random_seed)
        pos = random.randint(0, len(s))
        random_character = chr(random.randrange(32, 127))
        return s[:pos] + random_character + s[pos:]

    def _replace_random_character(self, s):
        """Returns s with a random character replaced"""
        if(self.random_seed):
            random.seed(self.random_seed)
        if s == "":
            return ""
        pos = random.randint(0, len(s) - 1)
        random_character = chr(random.randrange(32, 127))
        return s[:pos] + random_character + s[pos + 1 :]


runs = 10
budget = 100

seed_1 = AbstractSeed("")
seed_2 = AbstractSeed("12 8")
seed_3 = AbstractSeed("Hello+my+guy")
seed_4 = AbstractSeed("Hello%45coded")
seed_5 = AbstractSeed("Other+test+%23%78%abcoded")

seeds = [seed_1,seed_2,seed_3,seed_4, seed_5]

def fuzzing(runs = 10, budget = 100, power_schedule = None, grammar = None, seeds =seeds ):
    sum_results = []
    for i in range(runs):
        fuzzer = CgiSchedule(AbstractExecutor(cgi_decode), power_schedule = power_schedule, grammar=grammar, seeds = seeds)
        results = fuzzer.run_fuzzer(budget=budget)["coverage"]
        if (i == 0):
            sum_results.extend(results)
        else:
            for j in range(len(results)):
                sum_results[j] += results[j]
    for i in range(len(sum_results)):
        sum_results[i] = sum_results[i] / runs

    return sum_results

# Grammar definition :
letters = list(string.ascii_letters)
letters.extend(['1','2','3','4','5','6','7','8','9',''])
gram = {
    "<start>":["<encoded-string>"],
    "<encoded-string>":["<no-space-text>","<space-text>","<percentage-text>"],
    "<no-space-text>": ["<letter>","<letter><no-space-text>"],
    "<letter>":letters,
    "<space-text>":["<no-space-text>+<no-space-text>"],
    "<percentage-text>":["<no-space-text>%<hexadecimal-number>", "<no-space-text>%<hexadecimal-number><no-space-text>"],
    "<hexadecimal-number>":['<number><number>'],
    "<number>":['1','2','3','4','5','6','7','8','9','a','b','c','d','e','f','A','B','C','D','E','F']
}

grammar = AbstractGrammar(gram)
power_schedule = AbstractPowerSchedule()

#with_only_power_schedule = fuzzing(power_schedule = power_schedule)
#with_power_schedule_and_grammar = fuzzing(power_schedule = power_schedule, grammar= grammar)



#print(f" With only power schedule : {with_only_power_schedule}")
#print(f" With Power schedule and grammar  : {with_power_schedule_and_grammar}")
# getting the results

