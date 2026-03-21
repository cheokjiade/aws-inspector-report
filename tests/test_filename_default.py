from unittest.mock import patch, MagicMock
from datetime import datetime
import sys
from report import main

@patch("report.boto3.client")
@patch("report.get_account_id")
@patch("report.datetime")
@patch("report.write_report")
def test_main_uses_default_filename(mock_write, mock_datetime, mock_get_account_id, mock_boto_client):
    # Setup
    mock_get_account_id.return_value = "111222333444"
    
    # Mock datetime.now()
    mock_now = MagicMock()
    mock_now.strftime.return_value = "260309-1430"
    mock_datetime.now.return_value = mock_now
    
    # Mock boto client to return empty findings
    mock_client = MagicMock()
    mock_boto_client.return_value = mock_client
    paginator = MagicMock()
    mock_client.get_paginator.return_value = paginator
    paginator.paginate.return_value = [{"findings": []}]
    
    # Run main with no arguments (which means no --output)
    sys.argv = ["report.py"]
    main()
    
    # Verify the output filename passed to write_report
    # The default should be 111222333444-inspector-report-260309-1430.xlsx
    expected_filename = "111222333444-inspector-report-260309-1430.xlsx"
    
    # check if the first call to write_report has the expected filename as its first arg
    mock_write.assert_called_once()
    actual_filename = mock_write.call_args[0][0]
    assert actual_filename == expected_filename
