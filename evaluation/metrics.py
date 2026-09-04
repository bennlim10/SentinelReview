from collections import Counter

from evaluation.models import BinaryMetrics, TargetResult


def ratio(numerator: int, denominator: int) -> float | None:
    return numerator / denominator if denominator else None


def binary_metrics(results: list[TargetResult], *, changed: bool = False) -> BinaryMetrics:
    statuses = [result.changed_line_status if changed else result.status for result in results]
    counts = Counter(statuses)
    tp, fp, tn, fn = (counts[name] for name in ("tp", "fp", "tn", "fn"))
    precision = ratio(tp, tp + fp)
    recall = ratio(tp, tp + fn)
    return BinaryMetrics(true_positives=tp, false_positives=fp, true_negatives=tn,
        false_negatives=fn, unscorable=counts["unscorable"],
        scanner_errors=counts["scanner_error"], precision=precision, recall=recall,
        false_positive_rate=ratio(fp, fp + tn),
        f1=ratio(2 * tp, 2 * tp + fp + fn))
