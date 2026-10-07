"""LeakGuard core platform package (Stage S1 foundations).

Cross-cutting infrastructure shared by the HTTP layer and, in later
stages, the domain/provider/remediation packages:

  * errors         — ApiError + the structured error body contract
  * context        — per-request request_id (contextvars)
  * security       — security response headers
  * logging_setup  — structured, privacy-safe stderr logging

Standard library only, like the rest of the product.
"""
