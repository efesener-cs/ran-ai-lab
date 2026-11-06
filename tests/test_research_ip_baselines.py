import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from ai.research_ip_baselines import main,validate_partition
from checks.check_ip_research import PRIMARY_FEATURES,RICHER_OPTIONAL_FEATURES


class ResearchBaselineBoundaryTests(unittest.TestCase):
    def test_seed_overlap_is_rejected(self):
        with self.assertRaises(ValueError):validate_partition([1,2],[3],[4],[2])
        with self.assertRaises(ValueError):validate_partition([1],[],[3],[4])
        validate_partition([1,2],[3],[4],[5])

    def test_identity_and_ground_truth_are_not_features(self):
        fields=set(PRIMARY_FEATURES)|set(RICHER_OPTIONAL_FEATURES)
        self.assertTrue(fields.isdisjoint({'ipv4','source_ipv4','destination_ipv4','mac','source_mac',
            'source_port','destination_port','seed_group','source_group_id','window_index',
            'attack_applied','attack_tx_packets','benign_rx_ip_bytes'}))

    def test_existing_output_failure_does_not_overwrite_complete_status(self):
        with tempfile.TemporaryDirectory() as tmp:
            out=Path(tmp)/'finished';out.mkdir();status=out/'status.json';status.write_text('{"state":"complete"}\n')
            before=status.read_bytes()
            with patch('ai.research_ip_baselines.train',side_effect=FileExistsError):
                with self.assertRaises(FileExistsError):
                    main(['unused','--output',str(out),'--train-seeds','1','--validation-seeds','2','--evaluation-seeds','3','--ood-seeds','4'])
            self.assertEqual(status.read_bytes(),before)


if __name__=='__main__':unittest.main()
