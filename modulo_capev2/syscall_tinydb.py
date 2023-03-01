# module/reporting/syscall_tinydb.py
# [syscall_tinydb]
# enabled=on

import os
import json
import codecs

from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.exceptions import CuckooReportError

from tinydb import TinyDB, Query

class syscall_tinydb(Report):

        def run(self, results):

            try:
                db = TinyDB(os.path.join(self.reports_path, "syscall_tinydb.json"))

                table = db.table("Syscall TinyDB")

                nombre = results.get("target", {}).get("file", {}).get("name")

                signature = results.get("signatures", {})

                syscall_api = results.get("target", {}).get("file", {}).get("pe", {}).get("imports", {}).get("KERNEL32", {})

                syscall_tinydb = {
                                "NOMBRE": nombre,
                                "SIGNATURES": signature,
                                "APIs_KERNEL32": syscall_api
                }

                table.insert(syscall_tinydb)
                db.close()

            except (UnicodeError, TypeError, IOError) as e:
                raise CuckooReportError("Error al generar Syscall Tinydb report: %s" % e)