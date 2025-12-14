---
title: "How to count votes?"
publishDate: 2022-04-11 01:17:00 +0530
tags: [ ]
description: "Revealing the complexities and limitations of the seemingly simple process of voting and choosing a winner"
coverImage:
  src: "../../assets/images/count-votes/cover.jpg"
  "alt": "Voting"
slug: How-To-Count-Votes
---

<!--end_excerpt-->

  <script type="text/x-mathjax-config">
    MathJax.Hub.Config({
      tex2jax: {
        skipTags: ['script', 'noscript', 'style', 'textarea', 'pre'],
        inlineMath: [['$','$']]
      }
    });
  </script>
  <script src="https://cdn.mathjax.org/mathjax/latest/MathJax.js?config=TeX-AMS-MML_HTMLorMML" type="text/javascript"></script>

Voting is ubiquitous, be it as crucial as choosing a country's head of government, head of a student body, or answering
something as trivial as "What movie should we watch?". It arises naturally from the need to aggregate the varying
individual preferences into a singular outcome. Yet, rarely will you think about the voting system that chooses this
outcome, even when it can drastically change the result of the vote. What are the voting systems that I am talking
about? To explain, let us start with perhaps the most simple and popular ones:

* [Majority Rule](https://en.wikipedia.org/wiki/Majority_rule): Chose the outcome with the majority (more than half) of
  votes.
* [Plurality Voting](https://en.wikipedia.org/wiki/Plurality_voting) (also called first-past-the-post): Chose the
  outcome with the most votes (irrespective of whether it's a majority or not)

There are tons of others, a few of which I shall come to later in this post. Hereafter, to make things more intuitive, I
assume we are voting to choose a representative.

A very obvious flaw with the majority rule is that no candidate may get the majority in the case of more than two
candidates. This may render it useless in many cases. After all, we don't want to restrict ourselves to two choices, Do
we? So we resort to a plurality vote.

### Plurality Vote

That is, the candidate with the most votes is the winner. Very simple and logical. But is it? To illustrate the problem
with plurality voting, Let's pick up an example. Say Nehru, Patel, Azad, and Shastri contest an election for the head of
the student body. Their vote tally is given below:

| Candidate | Votes |
|-----------|-------|
| Nehru     | 20%   |
| Patel     | 19%   |
| Azad      | 20%   |
| Shastri   | 21%   |

Under plurality voting, Shastri wins the election. An obvious flaw of plurality voting is that a candidate can win with
very few votes. If the number of candidates increases to $N$, a candidate can win with as little as a single vote more
than $\frac{1}{N}$ of the total votes. Hence, In such cases, plurality voting is not very good at representing the
choice of all the voters. Let's move on to other problems with this voting system.

​ Now, Let's say Nehru and Shastri are the usual two candidates, polar opposites on the political spectrum. Fierce
competition between the two makes the outcome very uncertain each year and the margin of winning very small. Patel, an
ally of Nehru has an disagreement with Nehru. So he decides to nominate himself for the election. In the election, many
people more closely aligned with Patel than Nehru voted for Patel instead. The final outcome is given below:

| Candidate | Votes |
|-----------|-------|
| Patel     | 5%    |
| Nehru     | 47%   |
| Shastri   | 48%   |

Under plurality voting, Shastri wins the election easily. Let's see what has happened here. By being closer to Nehru on
the political spectrum, Patel took a larger chuck out of voters who prefer Nehru to Shastri. Patel's nomination leaves
the majority (the 47% and the 5% who would have chosen Nehru over Shastri in the absence of Patel) dissatisfied with the
result. This is called the Spoiler effect or [Vote Splitting](https://en.wikipedia.org/wiki/Vote_splitting).

​ The following year comes. People who prefer Patel (a small but significant share of all voters) realize that he can
never win, and thus their votes are [wasted](https://en.wikipedia.org/wiki/Wasted_vote). So they vote against their
first preference (aka Patel) and vote for their second preference (aka Nehru) instead. This problem is
called [tactical voting](https://en.wikipedia.org/wiki/Tactical_voting), where voters vote against their actual
preference.

​ Despite his best intentions, Patel realizes the problem and drops out of the race the following year. After observing
the whole fiasco, no third candidate stood up (or was forced to sit down) for elections ever since. The election thus
reverts back to its status quo of Nehru vs. Shastri. As we can observe, this voting system tends to reduce the number of
candidates two. This is called [Duverger's law](https://en.wikipedia.org/wiki/Duverger%27s_law). This is not always
true, but more often is the case.

The problems above can be summarized by the following statement that I quote from Wikipedia:

`All votes for anyone other than the second place are votes for the winner`

Is this particularly unfavorable outcome a fault of the candidates? or is it of the voters? Perhaps a large share of the
blame goes to the voting system used to decide the winner, aka plurality voting. Something either so sneaky that no one
noticed or so simple that no one chose to question.

Now, let me present another voting systems that can be used to decide the winner.

### [Condorcet method](https://en.wikipedia.org/wiki/Condorcet_method#Basic_procedure) (or pairwise majority)

This method extends the majority rule that allows for more than two candidates. It chooses a candidate who wins every
head-to-head majority election against the other candidates. The winner is known as the Condorcet winner. Note that we
don't actually need to conduct multiple elections. We just need to collect each voter's complete preference order, i.e.,
their ranking of each candidate.

The set of preference ordering of all voters is called
the [preference profile](https://en.wikipedia.org/wiki/Arrow's_impossibility_theorem#Formal_statement_of_the_theorem).
Any voting system that uses the complete preference profile is called
a [ranked or ordinal voting system](https://en.wikipedia.org/wiki/Ranked_voting). Intuitively, we can see why this
method is less vulnerable to tactical voting than the plurality voting.

Any voting system that chooses the Condorcet winner is said to satisfy
the [Condorcet winner criterion](https://en.wikipedia.org/wiki/Condorcet_winner_criterion). Observe that the plurality
vote violates this criterion. So far, so good. What's the problem with this method? Well, the Condorcet winner may not
always exist. It may lead to cyclical preferences causing
a [Condorcet paradox](https://en.wikipedia.org/wiki/Condorcet_paradox). Let's illustrate this problem with an example:

|     | Voter 1 | Voter 2 | Voter 3 |
|-----|---------|---------|---------|
| 1st | Patel   | Azad    | Nehru   |
| 2nd | Azad    | Nehru   | Patel   |
| 3rd | Nehru   | Patel   | Azad    |

In Patel vs Azad, Patel wins 2 vs 1; in Azad vs Nehru, Azad wins 2 vs 1 yet in Nehru vs Patel, Nehru wins 2 vs 1. It's
This leads to a paradox! From transitive individual preferences, we have arrived at cyclical societal preferences!

### [Borda count](https://en.wikipedia.org/wiki/Borda_count)

Also a ranked voting system. When counting a vote, the highest-ranked candidate gets $n-1$ points & the lowest-ranked
candidate gets $0$ points. A candidate's score is simply the sum of their points across all votes. And the candidate
with the highest score wins. Observe that this voting system considers all of a voter's preferences, not just the most
preferred candidate. But it violates the Condorcet winner criterion and other two essential properties that we wish any
voting system should have, namely, Majority Criterion and Independence of irrelevant alternatives.

* [Majority Criterion](https://en.wikipedia.org/wiki/Majority_criterion): A candidate having a majority must win under
  this criterion.
* [Independence of irrelevant alternatives (IIA)](https://en.wikipedia.org/wiki/Independence_of_irrelevant_alternatives):
  Quoting from Wikipedia:
  `The social preferences between alternatives x and y depend only on the individual preferences between x and y` or
  `if one candidate x would win an election, and if a new candidate y were added to the ballot, then either x or y would win the election`

Lets see the above two criteria with an example:

|     | 54%     | 30%     | 16%     |
|-----|---------|---------|---------|
| 1st | Patel   | Azad    | Shastri |
| 2nd | Azad    | Shastri | Patel   |
| 3rd | Nehru   | Nehru   | Nehru   |
| 4rd | Shastri | Patel   | Azad    |

Out of, say, 100 votes, the final score of the candidates will be Patel (194), Azad (198), Nehru (100), and Shastri (
108). Hence, Azad wins the election despite Patel having a majority! This violates the majority criterion. Also, notice
that if Nehru is eliminated, Patel wins the election. Thus, this voting system violates the IIA property too.

### [Instant Runoff Voting](https://en.wikipedia.org/wiki/Instant-runoff_voting)

A ranked voting system like the above two. The method works a little differently:

It repeats the following steps until only one candidate remains:

1. Tally the votes
2. Eliminate the candidate with the least votes, thus making him current last.
3. Distribute all the eliminated candidate's votes according to the voter's next preferred candidate.

Let's see what happens in our previous example of "Nehru vs Shastri" from plurality voting. Suppose, given the scenario
as discussed previously in plurality voting, we get the following preference profile:

|     | 47%     | 48%     | 4%      | 1%      |
|-----|---------|---------|---------|---------|
| 1st | Nehru   | Shastri | Patel   | Patel   |
| 2nd | Patel   | Patel   | Nehru   | Shastri |
| 3rd | Shastri | Nehru   | Shastri | Nehru   |

Patel gets only 5% (4% + 1%) of the votes, thus placing him last in the third position. The votes of those who voted for
Patel are distributed among their second preferences. Therefore in the next round, the tally is as follows: Nehru: 51% (
the original 47% and 4% who put Nehru as their second choice) and Shastri: 49% (48% + 1% from second choice).

Now Shastri is eliminated (gets 2nd position), and Nehru wins the election. And the majority is happy with this outcome.
While this voting system does not entirely eliminate the problem of tactical voting and spoiler effect that we discussed
above, it does reduce them to a great extent. In fact, it can be shown that no ranked voting system is resistant to
tactical voting! A result know
as [Gibbard-Satterthwaite Theorem](https://en.wikipedia.org/wiki/Gibbard%E2%80%93Satterthwaite_theorem). Also this
voting system satisfies the majority criterion but violates IIA and Condorcet winner criterion. It also violates another
important property we wish any voting system should have, aka Monotonicity.

* [Monotonicity](https://en.wikipedia.org/wiki/Monotonicity_criterion):  Again, quoting from Wikipedia,
  `A ranked voting system is monotonic if it is neither possible to  prevent the election of a candidate by ranking them higher on some of  the ballots, nor possible to elect an otherwise unelected candidate by  ranking them lower on some of the ballots`

Let's illustrate monotonicity with an example:

|     | 39%   | 35%   | 26%   |
|-----|-------|-------|-------|
| 1st | Patel | Azad  | Nehru |
| 2nd | Azad  | Nehru | Patel |
| 3rd | Nehru | Patel | Azad  |

Under instant-runoff-vote, Patel wins the election. But let's see what happens when 10% out of the 35% who put Azad
first move their support to Patel, i.e., the currently winning candidate.

|     | 49%   | 25%   | 26%   |
|-----|-------|-------|-------|
| 1st | Patel | Azad  | Nehru |
| 2nd | Azad  | Nehru | Patel |
| 3rd | Nehru | Patel | Azad  |

We observe that Nehru wins the election. An increase in the votes of Patel led him to lose the election! This might seem
like a paradox. But if you ponder over it closely, you realize that it's not Patel getting more votes that caused him to
lose the election, But it's, in fact, the change in the distribution of other candidates' votes. The 10% votes could
have gone to a fourth candidate or been thrown away into oblivion, yet the outcome would remain the same.

### The limitations

The four criteria that I have shown above are called fairness criteria. These are some of the properties that we expect
a good voting system will fulfill. Yet non of the four voting methods that we saw earlier satisfies all of them
simultaneously. Unfortunately, as it turns out, no ordinal voting system can satisfy all of them simultaneously. This
famous result is know as [Arrow's Impossibility Theorem](https://en.wikipedia.org/wiki/Arrow%27s_impossibility_theorem)

We have yet to address other problems that are not about the voting systems themselves. They are about how the
preferences (aka the votes) were collected. Remember, we asked the voters to list the candidates in order of their
preference. In doing so, we inherently have made some assumptions such
as [Transitivity of preferences](https://en.wikipedia.org/wiki/Preference_(economics)). That is, for any two
choices $a$ & $b$, we have $a\succeq b$ (read it as "a is at-least as good as b, if not better")
and $b\succeq c$  $\implies$ $a\succeq c$ . Is this always the case? If I prefer $a$ over $b$ & $b$ over $c$, does it
always mean I prefer $a$ over $c$. Can the opposite not be the case? Another assumption
is [Completeness of preferences](https://en.wikipedia.org/wiki/Preference_(economics)). That is, Given two choices, $a$
and $b$, we have either $a\succeq b$ or $b\succeq a$. In other words, you always have a preference.

Indeed, you would have encountered some situations in your life where this is not the case. For the folks from IIT KGP,
remember choosing the preference order for the breadth allocation and how frustrating the task is? Whether or not these
two assumptions are correct is a subjective or philosophical question. Nevertheless, these are reasonable assumptions
about individual preferences, allowing us to proceed further.

### Cardinal voting to the rescue?

In this post, I have completely ignored another class of voting systems
called [cardinal voting systems](https://en.wikipedia.org/wiki/Cardinal_voting) that may allow us to escape the Arrow's
impossibility theorem. Instead of asking for a preference order, we can ask the voters to assign a rating to each
candidate. Notice that we make even stronger assumptions about individual preferences than those discussed above. If
cardinal voting is allowed, It will convey more information about voters' preferences. It would also allow us to answer
questions like "How much do I prefer a over b? And what about in comparison to my preference of b over c?". It would
also allow us to compare utilities across individuals. But, in doing so, we do something called
`interpersonal comparisons of utility`. It raises the question of whether there is a meaningful way to compare utility
across different individuals?

### Concluding remarks

This is frustrating, isn't it? We have reached the end of the post and yet are left with more questions than answers. In
the absence of a "perfect voting system" which voting system should we go for? What criterion should we relax? Does
Arrow's impossibility theorem mean that we are collectively doomed to choose bad outcomes? Or a more practical question
of why we go with plurality voting despite its apparent flaws? This is just the tip of the iceberg. The issue of
collecting individual preferences to reach a collective decision is, in fact, a fascinating area of study itself,
called [Social Choice Theory](https://en.wikipedia.org/wiki/Social_choice_theory). Owing to the length of this post, I
have avoided formal mathematical definitions and frameworks used to analyze this issue. Few of the results & paradoxes
that arise in this subject will simply blow one's mind. But perhaps, I have fulfilled my motive to make you realize the
importance of the voting systems and how we can go far beyond simple majority or plurality voting. So next time you
vote, question yourself, "Given the context of the vote, does this particular voting system work properly? Or can we do
better?".

### References

1. [Politics in the Animal Kingdom — CGP Grey](https://www.cgpgrey.com/politics-in-the-animal-kingdom/) (Nice videos
   demonstrating few of the voting systems)
2. [A Primer in Social Choice Theory](https://www.amazon.com/Primer-Social-Choice-Theory-Perspectives/dp/0199565309)
3. [Voting Research - Voting Theory](https://www.princeton.edu/~cuff/voting/theory.html)
4. [FairVote - Monotonicity](http://archive.fairvote.org/monotonicity/)
5. [Theory of Voting](https://people.math.wisc.edu/~meyer/math141/voting2.html)
6. [http://math.hawaii.edu/~marriott/teaching/summer2013/math100/violations.pdf](http://math.hawaii.edu/~marriott/teaching/summer2013/math100/violations.pdf)
