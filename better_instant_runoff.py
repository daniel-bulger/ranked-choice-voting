from collections import defaultdict
import math

# Returns the candidates ordered by their general preference, from best to worst.
# |candidates| is a list of integers representing candidate ids.
# |ranking_per_voter| is a list of rankings, where each ranking is a list of candidate ids in order from best to worst.
# The algorithm counts the top n/2 votes where n is the number of remaining candidates.
def run_instant_runoff_election(ranking_per_voter, debug=False):
    candidates_with_votes = []
    for ranking in ranking_per_voter:
        for candidate in ranking:
            candidates_with_votes.append(candidate)
    return run_instant_runoff_helper(list(set(candidates_with_votes)), ranking_per_voter, debug)

def run_instant_runoff_helper(candidates, ranking_per_voter, debug=False):
    if len(candidates) <= 1:
        if debug:
            print("Winner is candidate " + str(candidates[0]))
        my_votes = [[]]
        for candidate in ranking_per_voter[0]:
            if candidate == candidates[0]:
                my_votes = [[candidate]]
        return [defaultdict(int, {candidates[0]: len(ranking_per_voter)})], candidates, my_votes
    if debug:
        print("Running voting round with candidates:" + str(candidates))
    last_candidate_to_count_per_voter = math.ceil(len(candidates) / 2)
    votes = defaultdict(int)
    for candidate in candidates:
        votes[candidate] = 0
    my_votes = []
    for idx, ranking in enumerate(ranking_per_voter):
        i = 0
        for candidate in ranking:
            if i >= last_candidate_to_count_per_voter: break
            if candidate not in candidates: continue
            votes[candidate] += 1
            if idx == 0:
                my_votes.append(candidate)
            i += 1
    if debug:
        print("Votes per candidate:")
        print(votes)
    worst_candidate = min(votes, key=votes.get)
    candidates.remove(worst_candidate)
    for ranking in ranking_per_voter:
        try:
            ranking.remove(worst_candidate)
        except ValueError:
            pass
    next_rounds, remaining_candidates, my_next_votes = run_instant_runoff_helper(candidates, ranking_per_voter, debug)
    return [votes] + next_rounds, remaining_candidates + [worst_candidate], [my_votes] + my_next_votes

def test_instant_runoff_election():
    print(run_instant_runoff_election([[1,2,3,4],[1,2,3,4],[4,3,2,1]],debug=True)) # Should return 1,2,3,4
    print(run_instant_runoff_election([[3,1,2,4],[4,1,2,3],[2,1,3,4]],debug=True)) # Should return 1 first
    print(run_instant_runoff_election([[3,1],[4,1],[2,1]],debug=True)) # Should return 1 first
    print(run_instant_runoff_election([[3,1,2,4],[4],[2,1,3,4],[5,1]],debug=True)) # Should return 1 first

if __name__ == "__main__":
    test_instant_runoff_election()