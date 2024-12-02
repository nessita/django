from django.utils.deprecation import RemovedInDjango60Warning, emit_warning

try:
    import oracledb

    is_oracledb = True
except ImportError as e:
    try:
        import cx_Oracle as oracledb  # NOQA

        emit_warning(
            "cx_Oracle is deprecated. Use oracledb instead.",
            RemovedInDjango60Warning,
            stacklevel=2,
        )
        is_oracledb = False
    except ImportError:
        raise e from None
