import time
from typing import Dict, Iterable, List, Optional

from paloaltosdk.pa_utils import PanoramaAPI


class PanoramaAPITestHarness(PanoramaAPI):
    """
    Test harness for PanoramaAPI that marks the most recently submitted
    VSYS creation serial(s) as having an active job (status ACT).

    Usage:
        pano = PanoramaAPITestHarness(active_ttl_seconds=180)
        pano.IP = 'panorama.mgmt'
        pano.Username = 'user'; pano.Password = 'pass'; pano.login()
        pano.create_vsys('vsysX', 'auto', serial='0123456789')
        pano.has_active_jobs('0123456789')  # -> True during TTL
    """

    def __init__(self, panorama_mgmt_ip: Optional[str] = None, active_ttl_seconds: int = 180):
        super().__init__(panorama_mgmt_ip=panorama_mgmt_ip)
        # Map of serial -> expiry_epoch
        self._forced_active: Dict[str, float] = {}
        self._active_ttl_seconds = active_ttl_seconds

    # ---------- Internals ----------
    def _now(self) -> float:
        return time.time()

    def _prune_expired(self) -> None:
        now = self._now()
        expired = [s for s, exp in self._forced_active.items() if exp <= now]
        for s in expired:
            self._forced_active.pop(s, None)

    def _mark_active(self, serials: Iterable[str]) -> None:
        expiry = self._now() + max(1, int(self._active_ttl_seconds))
        for s in serials:
            if s:
                self._forced_active[str(s)] = expiry

    def _fabricate_job(self, serial: str, status: str = "ACT") -> dict:
        # Minimal shape consistent with PanoramaAPI.get_jobs_for_serial expectations
        return {
            'id': f'test-{int(self._now())}',
            'status': status,
            'type': 'Commit',
            'user': getattr(self, 'Username', 'tester'),
            'progress': '0',
            'devices': {
                'entry': {'@name': serial}
            }
        }

    # ---------- Public controls ----------
    def set_active_ttl_seconds(self, seconds: int) -> None:
        self._active_ttl_seconds = int(seconds)

    def force_active_for(self, serials: Iterable[str], seconds: Optional[int] = None) -> None:
        if seconds is not None:
            prev = self._active_ttl_seconds
            self._active_ttl_seconds = int(seconds)
            try:
                self._mark_active(serials)
            finally:
                self._active_ttl_seconds = prev
        else:
            self._mark_active(serials)

    def clear_forced_active(self, serials: Optional[Iterable[str]] = None) -> None:
        if serials is None:
            self._forced_active.clear()
        else:
            for s in serials:
                self._forced_active.pop(str(s), None)

    # ---------- Overrides to inject behavior ----------
    def create_vsys(self, vsys_name: str, vsys_id: str, serial: int, tag_name: Optional[str] = None,
                    make_changes_on_active_ha_peer: bool = False):
        # Ensure non-None type for tag_name to satisfy base signature typing
        safe_tag = tag_name if tag_name is not None else ""
        resp = super().create_vsys(vsys_name, vsys_id, serial, safe_tag, make_changes_on_active_ha_peer)
        # After successful creation, mark this serial as having an active job for a bit.
        self._mark_active([str(serial)])
        return resp

    def get_jobs_for_serial(self, serial: str, statuses: Optional[Iterable[str]] = ("ACT", "PEND", "QUEUED")) -> List[dict]:
        # First return fabricated active job if within TTL
        self._prune_expired()
        if str(serial) in self._forced_active:
            job = self._fabricate_job(str(serial), status='ACT')
            if not statuses:
                return [job]
            status_val = job.get('status') or ''
            try:
                status_iter = list(statuses)
            except TypeError:
                status_iter = [str(statuses)]
            if status_val in status_iter:
                return [job]
        # Otherwise, fall back to real implementation
        return super().get_jobs_for_serial(serial, statuses=statuses)

    def has_active_jobs(self, serial: str, statuses: Optional[Iterable[str]] = ("ACT", "PEND", "QUEUED")) -> bool:
        self._prune_expired()
        if str(serial) in self._forced_active:
            return True
        return super().has_active_jobs(serial, statuses=statuses)
