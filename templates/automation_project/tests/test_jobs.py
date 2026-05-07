import unittest
from tempfile import TemporaryDirectory
from pathlib import Path

from app.jobs import JobTracker


class JobTrackerTests(unittest.TestCase):
    def test_persists_and_loads_jobs(self):
        with TemporaryDirectory() as tmpdir:
            state_path = Path(tmpdir) / "jobs_state.json"
            tracker = JobTracker.load_state(state_path)
            job = tracker.create(
                "install",
                "hydra, dirb",
                details=["a installer: hydra, dirb"],
            )
            tracker.update(job.job_id, status="success", result="disponible(s): hydra, dirb")

            restored = JobTracker.load_state(state_path)

        self.assertEqual(restored.total_count, 1)
        restored_job = restored.recent()[0]
        self.assertEqual(restored_job.kind, "install")
        self.assertEqual(restored_job.status, "success")
        self.assertIn("hydra", restored_job.result)

    def test_running_jobs_are_loaded_as_waiting(self):
        with TemporaryDirectory() as tmpdir:
            state_path = Path(tmpdir) / "jobs_state.json"
            tracker = JobTracker.load_state(state_path)
            tracker.create("tool", "nmap 10.10.10.10", status="running")

            restored = JobTracker.load_state(state_path)

        restored_job = restored.recent()[0]
        self.assertEqual(restored_job.status, "waiting")
        self.assertEqual(restored.active_count, 1)

    def test_cancel_marks_job_inactive_and_persists_result(self):
        tracker = JobTracker()
        job = tracker.create("tool", "nmap 10.10.10.10", status="running")

        tracker.cancel(
            job.job_id,
            result="log partiel: /tmp/nmap.log",
            append_detail="annule par utilisateur",
        )

        self.assertEqual(job.status, "cancelled")
        self.assertFalse(job.is_active)
        self.assertEqual(tracker.active_count, 0)
        self.assertIn("/tmp/nmap.log", job.result)
        self.assertIn("annule par utilisateur", job.details)


if __name__ == "__main__":
    unittest.main()
