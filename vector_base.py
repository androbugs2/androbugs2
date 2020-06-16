from abc import ABC, abstractmethod

from androguard.core.analysis.analysis import Analysis
from androguard.core.bytecodes.apk import APK
from androguard.core.bytecodes.dvm import DalvikVMFormat

from androbugs import Writer


class VectorBase(ABC):
    """
    This abstract class is used to define vulnerability vectors for the AndroBugs vulnerability scanner.
    """

    def __init__(self, writer: Writer, apk: APK, dalvik: DalvikVMFormat, analysis: Analysis) -> None:
        """
        Initialize the vector class with the resources needed for analysis.
        :param writer: Output writer.
        :param apk: APK object.
        :param dalvik: Dalvik VM object.
        :param analysis: Analysis object.
        """
        self.writer = writer
        self.apk = apk
        self.dalvik = dalvik
        self.analysis = analysis

    @property
    @abstractmethod
    def description(self) -> str:
        """
        Short description of the vulnerability vector.
        :return: str
        """
        pass

    @abstractmethod
    def analyze(self) -> None:
        """
        Analyze the application for the described vulnerability.
        Results may be passed to the writer.
        :return: None
        """
        pass
