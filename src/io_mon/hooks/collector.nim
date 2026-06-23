import io_mon/types
import io_mon/writer

proc finalizeMonitorFragments*(fragmentDir, outputPath: string): MonitorDepFile =
  mergeFragments(fragmentDir, outputPath)
