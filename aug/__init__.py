"""Arch Update Guard: pacman/AUR güncellemelerini inceleyen yerel pano."""

__version__ = "0.1.0"
APP_NAME = "Güncelleme Bekçisi"  # Turkish name; see app_name()


def app_name() -> str:
    from .i18n import t
    return t(APP_NAME)
APP_ID = "arch-update-guard"
