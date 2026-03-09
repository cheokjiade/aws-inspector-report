#!/usr/bin/env python3
"""AWS Inspector v2 ECR vulnerability report generator."""

import argparse
import sys
from datetime import datetime, timezone


SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNTRIAGED"]
AGE_BUCKETS = ["< 30 days", "30-60 days", "60-90 days", "> 90 days"]


def main():
    pass


if __name__ == "__main__":
    main()
