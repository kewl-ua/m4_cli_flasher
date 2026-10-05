"""The console view of a flash: one line per stage, bars redrawn in place."""
import io
import unittest

from dji_duml.display import ProgressView
from dji_duml.flasher import Progress, Stage


def run(events, total=666_000_000, **options):
    clock = [0.0]
    out = io.StringIO()
    with ProgressView(total, stream=out, monotonic=lambda: clock[0], **options) as view:
        for event in events:
            if isinstance(event, float):
                clock[0] += event
            else:
                view(event)
    return out.getvalue()


FLASH = [Progress(Stage.PREFLIGHT), Progress(Stage.ENTER),
         *[item for percent in range(101) for item in (0.6, Progress(Stage.TRANSFER, percent))],
         Progress(Stage.START), Progress(Stage.VERIFY),
         30.0, Progress(Stage.UPGRADING, 3), 30.0, Progress(Stage.UPGRADING, 43),
         Progress(Stage.REBOOT), 20.0, Progress(Stage.UPGRADING, 73),
         Progress(Stage.DONE, 100, "17.02.0501")]


class ProgressViewTests(unittest.TestCase):
    def test_terminal_redraws_one_line_per_stage(self):
        text = run(FLASH, interactive=True)
        lines = text.split("\n")
        self.assertEqual(len(lines), 10)  # 9 lines and the empty rest
        transfer = lines[2].split("\r")
        self.assertEqual(len(transfer), 102)  # the leading \r, then 101 redraws
        widths = {redraw.rindex("]") - redraw.index("[", 10) for redraw in transfer[1:]}
        self.assertEqual(len(widths), 1, "the bar keeps its width")
        self.assertIn("100%  11.1 MB/s  in 1:00", transfer[-1])
        self.assertIn(" 50%  11.1 MB/s  0:30 left", transfer[51])
        self.assertTrue(lines[3].endswith("start  requesting the install"))
        self.assertIn(" 43%  install since ", lines[5])
        self.assertTrue(lines[6].endswith("reboot  the device restarts; reconnecting"))
        self.assertIn(" 73%  install since ", lines[7])
        self.assertTrue(lines[8].endswith("done  17.02.0501"))

    def test_redraw_clears_a_longer_previous_text(self):
        text = run([Progress(Stage.TRANSFER, 50), 1.0, Progress(Stage.TRANSFER, 51)],
                   interactive=True, total=None)
        first, second = text.strip("\n").split("\r")[1:]
        self.assertGreaterEqual(len(second), len(first))

    def test_log_gets_ten_percent_steps(self):
        text = run(FLASH, interactive=False)
        self.assertNotIn("\r", text)
        transfer = [line for line in text.splitlines() if "] transfer" in line]
        self.assertEqual([line.split("]")[2].split("%")[0].strip() for line in transfer],
                         [str(percent) for percent in range(0, 101, 10)])

    def test_verbose_prints_every_report(self):
        text = run(FLASH, verbose=True)
        self.assertNotIn("\r", text)
        self.assertEqual(sum("] transfer " in line for line in text.splitlines()), 101)
        self.assertIn("] done 100% 17.02.0501", text)

    def test_log_keeps_the_last_percent_before_a_stage_change(self):
        text = run([Progress(Stage.UPGRADING, 3), Progress(Stage.UPGRADING, 73),
                    Progress(Stage.UPGRADING, 77), Progress(Stage.REBOOT)], interactive=False)
        percents = [line.split("]")[2].split("%")[0].strip() for line in text.splitlines()
                    if "upgrading" in line]
        self.assertEqual(percents, ["3", "73", "77"])

    def test_a_broken_stream_is_left_alone(self):
        class Closed(io.StringIO):
            def write(self, text):
                raise OSError(22, "Invalid argument")

        view = ProgressView(stream=Closed(), interactive=True)
        view(Progress(Stage.TRANSFER, 10))
        view(Progress(Stage.TRANSFER, 20))
        view.close()

    def test_an_open_line_is_ended_on_errors(self):
        out = io.StringIO()
        with self.assertRaises(RuntimeError), ProgressView(stream=out, interactive=True) as view:
            view(Progress(Stage.TRANSFER, 40))
            raise RuntimeError
        self.assertTrue(out.getvalue().endswith("\n"))


if __name__ == "__main__":
    unittest.main()
