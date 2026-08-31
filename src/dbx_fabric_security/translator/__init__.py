from dbx_fabric_security.translator.cls_translator import ClsEntitlement, translate_cls
from dbx_fabric_security.translator.rls_translator import RlsEntitlement, translate_rls
from dbx_fabric_security.translator.role_builder import build_fabric_roles

__all__ = [
    "ClsEntitlement",
    "translate_cls",
    "RlsEntitlement",
    "translate_rls",
    "build_fabric_roles",
]
