from poly_fuzzer.fuzzers.abstract_fuzzer import AbstractFuzzer
from urllib.parse import urlparse
from poly_fuzzer.common.abstract_executor import AbstractExecutor
from poly_fuzzer.common.abstract_seed import AbstractSeed
from poly_fuzzer.fuzzers.mutation_fuzzer import MutationFuzzer
from poly_fuzzer.common.abstract_grammar import AbstractGrammar
import string, random
class UrlFuzzer(AbstractFuzzer):
    def __init__(self,
                 executor: AbstractExecutor,
                 seeds: list[AbstractSeed],
                 random_seed=None,
                 min_mutations: int = 1,
                 max_mutations: int = 10,

                 ):
        AbstractFuzzer.__init__(self, executor)
        self.seeds = seeds
        self.seed_index = 0
        self.random_seed = random_seed
        self.executor = executor
        self.min_mutations = min_mutations
        self.max_mutations = max_mutations
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
                self.seeds.append(AbstractSeed(input))

    def _create_candidate(self):
        if (self.random_seed):
            random.seed(self.random_seed)
        seed = random.choice(self.seeds)
        candidate = seed.data
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
def fuzzing(seeds, runs=10, budget=100, rand_seed=[ 55 + i  for i in range(runs) ]):
    sum_results = []
    for i in range(runs):
        cgi_fuzzer = UrlFuzzer(executor=AbstractExecutor(urlparse), seeds=seeds)
        results = cgi_fuzzer.run_fuzzer(budget=budget)["coverage"]
        if (i == 0):
            sum_results.extend(results)
        else:
            for j in range(len(results)):
                sum_results[j] += results[j]
    for i in range(len(sum_results)):
        sum_results[i] = sum_results[i] / runs

    return sum_results

# # Uncomment to get the different value with different runs and budget
# for i in range (3):
#     simple_fuzzing = fuzzing(seeds = seeds, runs = 10 +i*5, budget=100)
#     print(f"Runs {10+i*5} budget {100} - convergence - {max(simple_fuzzing)}")
#     other_fuzzing = fuzzing(seeds=seeds, runs = 10 +i*5, budget=200)
#     print(f"Runs {10+i*5} budget {200} - convergence - {max(other_fuzzing)}")

