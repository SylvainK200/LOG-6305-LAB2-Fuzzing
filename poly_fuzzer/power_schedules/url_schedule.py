from poly_fuzzer.fuzzers.abstract_fuzzer import AbstractFuzzer
from urllib.parse import urlparse
from poly_fuzzer.common.abstract_executor import AbstractExecutor
from poly_fuzzer.common.abstract_seed import AbstractSeed
from poly_fuzzer.fuzzers.mutation_fuzzer import MutationFuzzer
from poly_fuzzer.power_schedules.abstract_power_schedule import AbstractPowerSchedule
from poly_fuzzer.common.abstract_grammar import AbstractGrammar
import string, random
import numpy as np


class UrlSchedule(AbstractFuzzer):
    def __init__(self, executor: AbstractExecutor,
                 seeds,
                 power_schedule=None,
                 grammar=None,
                 random_seed=None,
                 min_mutations: int = 10,
                 max_mutations: int = 100):
        AbstractFuzzer.__init__(self, executor)
        self.seeds = seeds
        self.min_mutations = min_mutations
        self.max_mutations = max_mutations
        self.grammar = grammar
        self.seed_index = 0
        self.random_seed = random_seed
        self.power_schedule = power_schedule
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
                #print(f"New input : Grammar ? {self.grammar == None} " + input)
                self.seed_index +=1
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
        if (self.random_seed):
            random.seed(self.random_seed)
        mutator = random.choice(self.mutators)
        return mutator(s)

    def _delete_random_character(self, s):
        """Returns s with a random character deleted"""
        if (self.random_seed):
            random.seed(self.random_seed)
        if len(s) > 5:
            pos = random.randint(0, len(s) - 1)
            return s[:pos] + s[pos + 1:]
        else:
            return s

    def _insert_random_character(self, s):
        """Returns s with a random character inserted"""
        if (self.random_seed):
            random.seed(self.random_seed)
        pos = random.randint(0, len(s))
        random_character = chr(random.randrange(32, 127))
        return s[:pos] + random_character + s[pos:]

    def _replace_random_character(self, s):
        """Returns s with a random character replaced"""
        if (self.random_seed):
            random.seed(self.random_seed)
        if s == "":
            return ""
        pos = random.randint(0, len(s) - 1)
        random_character = chr(random.randrange(32, 127))
        return s[:pos] + random_character + s[pos + 1:]


runs = 10
budget = 100

seed_1 = AbstractSeed("www.google.com")
seed_2 = AbstractSeed("https://www.facebook.com/")
seed_3 = AbstractSeed("http://127.0.0.1:8080/index.html")
seed_4 = AbstractSeed("https://www.facebook.com")
seed_5 = AbstractSeed("https://www.facebook-com/")
seed_6 = AbstractSeed("http:/127.0.0.1:8080/index.htl")
seed_7 = AbstractSeed("http:/127..0.1:8080/index.htl")
seed_8 = AbstractSeed("http:/127.0.1:8080/index.htl")

seeds = [seed_1, seed_2, seed_3, seed_4, seed_5, seed_6, seed_7, seed_8]


def fuzzing(runs=10, budget=100, power_schedule=None, grammar=None, seeds=seeds):
    sum_results = []
    for i in range(runs):
        fuzzer = UrlSchedule(AbstractExecutor(urlparse), power_schedule=power_schedule, grammar=grammar, seeds=seeds)
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
numbers = ['0','1', '2', '3', '4', '5', '6', '7', '8', '9']
letters.extend(numbers)
gram = {
    '<start>':['<url>'],
    '<url>':['<first-part>www.<domain-name><other-part>', '<first-part><ip-address>:<port><other-part>'],
    '<first-part>':['http://', 'https://',''],
    '<domain-name>':['<text>.<extension>'],
    '<text>':['<letter><text>','<letter>'],
    '<letter>':letters,
    '<extension>':['<letter><extension>','<letter>'],
    '<other-part>':['/<text>','/<text><other-part>'],
    '<ip-address>':['<each-part>.<each-part>.<each-part>.<each-part>'],
    '<each-part>':['<digit>','<digit><digit>','1<digit><digit>','2<other-digits>'],
    '<port>':['<digit>','<digit><digit>','<digit><digit><digit>','<digit><digit><digit><digit>','<digit><digit><digit><digit><digit>'],
    '<other-digits>':numbers[:5],
    '<digit>':numbers,
}

grammar = AbstractGrammar(gram)
power_schedule = AbstractPowerSchedule()




# # Uncomment to get the different value with different runs and budget
# for i in range (3):
#      simple_fuzzing = fuzzing(seeds = seeds, runs = 10 +i*5, budget=100, power_schedule = power_schedule)
#      print(f"Runs {10+i*5} budget {100} - convergence - {max(simple_fuzzing)}")
#      other_fuzzing = fuzzing(seeds=seeds, runs = 10 +i*5, budget=200, power_schedule = power_schedule)
#      print(f"Runs {10+i*5} budget {200} - convergence - {max(other_fuzzing)}")
# #with_power_schedule_and_grammar = fuzzing(power_schedule = power_schedule, grammar= grammar)
#
# for i in range (3):
#     simple_fuzzing = fuzzing(seeds = seeds, runs = 10 +i*5, budget=100, power_schedule = power_schedule, grammar= grammar)
#     print(f" Grammar Runs {10+i*5} budget {100} - convergence - {max(simple_fuzzing)}")
#     other_fuzzing = fuzzing(seeds=seeds, runs = 10 +i*5, budget=200, power_schedule = power_schedule, grammar= grammar)
#     print(f" Grammar Runs {10+i*5} budget {200} - convergence - {max(other_fuzzing)}")

