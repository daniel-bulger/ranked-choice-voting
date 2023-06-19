from collections import defaultdict
import math

# Returns the candidates ordered by their general preference, from best to worst.
# |candidates| is a list of integers representing candidate ids.
# |ranking_per_voter| is a list of rankings, where each ranking is a list of candidate ids in order from best to worst.
# The algorithm counts the top 
def run_instant_runoff_election(ranking_per_voter):
    candidates_with_votes = []
    for ranking in ranking_per_voter:
        for candidate in ranking:
            candidates_with_votes.append(candidate)
    return run_instant_runoff_helper(list(set(candidates_with_votes)),ranking_per_voter)


def run_instant_runoff_helper(candidates,ranking_per_voter):
    if len(candidates) <= 1:
        return candidates
    last_candidate_to_count_per_voter = math.ceil(len(candidates) / 2)
    votes = defaultdict(int)
    for candidate in candidates:
        votes[candidate] = 0
    for ranking in ranking_per_voter:
        i = 0
        for candidate in ranking:
            if i >= last_candidate_to_count_per_voter: break
            if candidate not in candidates: continue
            votes[candidate] += 1
            i += 1
    worst_candidate = min(votes, key=votes.get)
    candidates.remove(worst_candidate)
    print(candidates)
    for ranking in ranking_per_voter:
        try:
            ranking.remove(worst_candidate)
        except ValueError:
            pass
    return run_instant_runoff_helper(candidates,ranking_per_voter) + [worst_candidate]


def test_instant_runoff_election():
    print(run_instant_runoff_election([[1,2,3,4],[1,2,3,4],[4,3,2,1]])) # Should return 1,2,3,4
    print(run_instant_runoff_election([[3,1,2,4],[4,1,2,3],[2,1,3,4]])) # Should return 1 first
    print(run_instant_runoff_election([[3,1],[4,1],[2,1]])) # Should return 1 first
    print(run_instant_runoff_election([[3,1,2,4],[4],[2,1,3,4],[5,1]])) # Should return 1 first

if __name__ == "__main__":
    test_instant_runoff_election()