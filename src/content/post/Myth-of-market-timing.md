---
title: "The Myth of Market Timing"
publishDate: 2024-12-26 01:50:00 +0530
tags: [ finance ]
description: "Trying to time the market with your monthly investments might seem appealing, but does it really pay off? or should you stick to good old-fashioned SIPs?"
coverImage:
  src: '../../assets/images/timing-the-market/cover.jpeg'
  alt: 'timing the market'
---

  <script type="text/x-mathjax-config">
    MathJax.Hub.Config({
      tex2jax: {
        skipTags: ['script', 'noscript', 'style', 'textarea', 'pre'],
        inlineMath: [['$','$']]
      }
    });
  </script>
  <script src="https://cdn.mathjax.org/mathjax/latest/MathJax.js?config=TeX-AMS-MML_HTMLorMML" type="text/javascript"></script>


It's the start of the month, and you see the market falling by several percentage points. So, you decide to hold off on
investing until the market conditions improve. What if it dips further, and I can get a better price? What if it
crashes?

The temptation to time the market is hard to resist, even for someone well-versed in finance. Financial wisdom says that
it doesn't work; in fact, SIPs are there to prevent you from doing so. But all this wisdom goes out the window when
emotions come into play. Even I have found myself trying to time the market several times. So, My
friend [@Puneet](https://www.linkedin.com/in/puneet--khandelwal/) and I decided to put our finance background to good
use and do a small analysis to determine if it works.

### Setup For The Analysis

We simulate an investment of a fixed amount in 'Nifty TRI' index every month using various strategies with some
constraints.

#### The Constraints

* Invest a fixed amount every month on Nifty TRI.
* Necessarily invest every month, irrespective of the market conditions.
* Only take long positions, So no liquidating any part of the portfolio.

These constraints might seem restrictive, but they keep things realistic and stop us from blurring the lines between
passive investing and active trading.

#### Back-testing Steps

* Back-test these strategies for an investment horizon of 1 to 15 years.
* Run each (strategy, investment horizon) pair for 1000 random time-periods sampled from historical data.
* Calculate the IRR for each iteration and report its average.

#### The Strategies

We came up with the following strategies:

* Invest on 5th/15th/25th of the month
* Invest when RSI(14) < 35/40/45 or month-end
* Invest when MACD histogram > 0 or month-end

To take things to the extreme, we've included a strategy where you magically end up investing on the exact day the index
hits its lowest point for the given month. Let's refer to this strategy as `Month Lowest`. This represents the upper
bound of performance with the given constraints.

### Back-testing Results

#### IRR Over Different Investment Horizons

|                      | **1 Year** | **3 Years** | **5 Years** | **10 Years** | **15 Years** |
|----------------------|-----------:|------------:|------------:|-------------:|-------------:|
| **Invest on 5th**    |     17.67% |      17.74% |      16.48% |       13.77% |       14.15% |
| **Invest on 15th**   |     17.41% |      17.72% |      16.47% |       13.77% |       14.17% |
| **Invest on 25th**   |     17.07% |      17.68% |      16.44% |       13.77% |       14.15% |
| **When RSI(14)<35**  |     16.28% |      17.39% |      16.28% |       13.69% |       14.09% |
| **When RSI(14)<40**  |     16.34% |      17.38% |      16.28% |       13.69% |       14.08% |
| **When RSI(14)<45**  |     16.51% |      17.41% |      16.31% |       13.70% |       14.08% |
| **When MACD Hist>0** |     17.92% |      17.88% |      16.55% |       13.82% |       14.20% |
| **Month Lowest**     |     26.57% |      20.80% |      18.27% |       14.66% |       14.70% |

**Note**: See [this](https://corporatefinanceinstitute.com/resources/valuation/internal-rate-return-irr/) to learn about
IRR.

#### Excess Returns Over 'Invest on 5th'

|                      | **1 Year** | **3 Years** | **5 Years** | **10 Years** | **15 Years** |
|----------------------|------------|-------------|-------------|--------------|--------------|
| **Invest on 5th**    | 0.00%      | 0.00%       | 0.00%       | 0.00%        | 0.00%        |
| **Invest on 15th**   | 0.00%      | \-0.04%     | \-0.04%     | \-0.03%      | 0.15%        |
| **Invest on 25th**   | \-0.05%    | \-0.07%     | \-0.10%     | \-0.04%      | \-0.01%      |
| **When RSI(14)<35**  | \-0.44%    | \-0.47%     | \-0.48%     | \-0.46%      | \-0.51%      |
| **When RSI(14)<40**  | \-0.48%    | \-0.49%     | \-0.48%     | \-0.47%      | \-0.58%      |
| **When RSI(14)<45**  | \-0.42%    | \-0.44%     | \-0.41%     | \-0.38%      | \-0.57%      |
| **When MACD Hist>0** | 0.12%      | 0.19%       | 0.16%       | 0.25%        | 0.46%        |
| **Month Lowest**     | 4.24%      | 4.40%       | 4.46%       | 4.84%        | 4.87%        |

**Note**: The Excess Return is defined
as <div style = "text-align:center;">$\text{Excess Returns} = \frac{\text{Final Value of Portfolio (Strategy)}}{\text{Final Value of Portfolio (Invest on 5th)}} - 1$</div>

### Observations

Notice how almost every strategy except 'Month Lowest' performs nearly the same as 'Invest on the 5th', if not
worse. The difference in both IRR and excess returns is marginal. These strategies may be too
simple to generate reliable buy signals. Maybe you can do better.

Now, let's look at the performance of 'Month Lowest', which is the maximum possible upper-bound of any strategy
you can cook up. Its IRR is ~9% higher than the simple strategy for an investment horizon of one year! It's amazing,
isn't it? Well, it isn't.

IRR can sometimes be misleading, especially for short investment horizons. Notice how its IRR
is converging towards the IRR of the simple strategy as the investment horizon increases. Also, the excess returns
remain around 4–5% irrespective of the investment horizon. **The excess returns from timing the market are not
compounding at all!** What's happening here?

### Why Timing The Market Doesn't Work

The results will feel more intuitive if you consider the index price as a sum of a trend and an oscillation around it.
While you may profit from the downsides in the short run, it will always be dwarfed by the trend in the long run. The
cost will almost always average out, which is precisely the whole point of investing
regularly. It frees you from trying to time the market.

Sure, the possible excess returns are not too small to simply ignore. But, you still have to devise a good strategy to
consistently time the market, which is going to be damn hard, if not impossible. You may be better off spending your
time & energy creating a better portfolio rather than trying to time the market.

### References

* [Code](https://github.com/puneet3476/timing_the_market)
