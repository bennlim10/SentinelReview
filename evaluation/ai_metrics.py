from collections import Counter

from evaluation.models import AIMetrics, TargetResult


def evaluate_ai(results: list[TargetResult]) -> AIMetrics:
    metrics = AIMetrics()
    priorities = Counter()
    # Combined case-target rows avoid counting the same AI review per scanner mode.
    for target in (item for item in results if item.mode == "combined"):
        if target.status == "fn":
            metrics.deterministic_misses_ai_cannot_recover += 1
        matches = [item for item in target.findings if item.target_match]
        reviews = [item.ai_review for item in matches if item.ai_review]
        for review in reviews:
            if review.status != "completed" or review.result is None:
                metrics.unavailable_reviews += 1
                continue
            metrics.available_reviews += 1
            output = review.result
            if output.verdict == "needs_review":
                metrics.needs_review += 1
                continue
            metrics.decisive_reviews += 1
            correct = ((output.verdict == "likely_valid" and target.status == "tp")
                       or (output.verdict == "likely_false_positive" and target.status == "fp"))
            key = f"{output.verdict}_{'correct' if correct else 'incorrect'}"
            setattr(metrics, key, getattr(metrics, key) + 1)
            (metrics.confidence_correct if correct else metrics.confidence_incorrect).append(output.confidence)
            if target.status == "tp" and output.verdict == "likely_false_positive":
                metrics.true_finding_downrank_risk += 1
        priorities.update(review.result.priority for review in reviews
                          if review.status == "completed" and review.result)
    metrics.priority_distribution = dict(priorities)
    return metrics
