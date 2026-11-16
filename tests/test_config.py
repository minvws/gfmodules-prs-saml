from app.config import ConfigLogging, read_ini_file


def test_the_example_config_reads_the_logging_streams() -> None:
    logging = ConfigLogging.model_validate(read_ini_file("app.conf.example")["logging"])

    assert logging.syslog_streams == ["app", "siem", "public_inspect"]
    assert logging.console_streams == ["debug"]
