# Canonical Confusion Attack

The canonical confusion attack demo is written in `tests/attacks/canonicalization_demo.cpp`. It shows that under a naive parsing strategy, 2 different parser implementations can derive 2 different interpretations of the same manifest, leading to a possible vulnerability. This is not the case however when using a strict parser which only parses manifests in the canonical form. Using a strict parser helps protect the behavioural consistency of the program leading to a reduced chance of a vulnerability developing.
