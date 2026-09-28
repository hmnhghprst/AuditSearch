# coding=utf-8
#
# Copyright © 2011-2024 Splunk, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License"): you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import sys

from .decorators import ConfigurationSetting
from .search_command import SearchCommand


# P1 [O] TODO: Discuss generates_timeorder in the class-level documentation for GeneratingCommand


class GeneratingCommand(SearchCommand):


    # region Methods

    def generate(self):

        raise NotImplementedError("GeneratingCommand.generate(self)")

    def _execute(self, ifile, process):

        if self._protocol_version == 2:
            self._execute_v2(ifile, self.generate())
        else:
            assert self._protocol_version == 1
            self._record_writer.write_records(self.generate())
        self.finish()

    def _execute_chunk_v2(self, process, chunk):
        count = 0
        records = []
        for row in process:
            records.append(row)
            count += 1
            if count == self._record_writer._maxresultrows:
                break

        for row in records:
            self._record_writer.write_record(row)

        if count == self._record_writer._maxresultrows:
            self._finished = False
        else:
            self._finished = True

    def process(
        self, argv=sys.argv, ifile=sys.stdin, ofile=sys.stdout, allow_empty_input=True
    ):
        """Process data.

        :param argv: Command line arguments.
        :type argv: list or tuple

        :param ifile: Input data file.
        :type ifile: file

        :param ofile: Output data file.
        :type ofile: file

        :param allow_empty_input: For generating commands, it must be true. Doing otherwise will cause an error.
        :type allow_empty_input: bool

        :return: :const:`None`
        :rtype: NoneType

        """

        if not allow_empty_input:
            raise ValueError(
                "allow_empty_input cannot be False for Generating Commands"
            )
        return super().process(
            argv=argv, ifile=ifile, ofile=ofile, allow_empty_input=True
        )

    # endregion

    # region Types

    class ConfigurationSettings(SearchCommand.ConfigurationSettings):
        """Represents the configuration settings for a :code:`GeneratingCommand` class."""

        # region SCP v1/v2 Properties

        generating = ConfigurationSetting(
            readonly=True,
            value=True,
            doc="""
            Tells Splunk that this command generates events, but does not process inputs.

            Generating commands must appear at the front of the search pipeline identified by :meth:`type`.

            Fixed: :const:`True`

            Supported by: SCP 1, SCP 2

            """,
        )

        # endregion

        # region SCP v1 Properties

        generates_timeorder = ConfigurationSetting(
            doc="""
            :const:`True`, if the command generates new events.

            Default: :const:`False`

            Supported by: SCP 1

            """
        )

        local = ConfigurationSetting(
            doc="""
            :const:`True`, if the command should run locally on the search head.

            Default: :const:`False`

            Supported by: SCP 1

            """
        )

        retainsevents = ConfigurationSetting(
            doc="""
            :const:`True`, if the command retains events the way the sort, dedup, and cluster commands do, or whether it
            transforms them the way the stats command does.

            Default: :const:`False`

            Supported by: SCP 1

            """
        )

        streaming = ConfigurationSetting(
            doc="""
            :const:`True`, if the command is streamable.

            Default: :const:`True`

            Supported by: SCP 1

            """
        )

        # endregion

        # region SCP v2 Properties

        distributed = ConfigurationSetting(
            value=False,
            doc="""
            True, if this command should be distributed to indexers.

            This value is ignored unless :meth:`type` is equal to :const:`streaming`. It is only this command type that
            may be distributed.

            Default: :const:`False`

            Supported by: SCP 2

            """,
        )

        type = ConfigurationSetting(
            value="streaming",
            doc="""
            A command type name.

            ====================  ======================================================================================
            Value                 Description
            --------------------  --------------------------------------------------------------------------------------
            :const:`'events'`     Runs as the first command in the Splunk events pipeline. Cannot be distributed.
            :const:`'reporting'`  Runs as the first command in the Splunk reports pipeline. Cannot be distributed.
            :const:`'streaming'`  Runs as the first command in the Splunk streams pipeline. May be distributed.
            ====================  ======================================================================================

            Default: :const:`'streaming'`

            Supported by: SCP 2

            """,
        )

        # endregion

        # region Methods

        @classmethod
        def fix_up(cls, command):
            """Verifies :code:`command` class structure."""
            if command.generate == GeneratingCommand.generate:
                raise AttributeError("No GeneratingCommand.generate override")

        # TODO: Stop looking like a dictionary because we don't obey the semantics
        # N.B.: Does not use Python 2 dict copy semantics
        def iteritems(self):
            iteritems = SearchCommand.ConfigurationSettings.iteritems(self)
            version = self.command.protocol_version
            if version == 2:
                iteritems = [
                    name_value1
                    for name_value1 in iteritems
                    if name_value1[0] != "distributed"
                ]
                if not self.distributed and self.type == "streaming":
                    iteritems = [
                        (name_value[0], "stateful")
                        if name_value[0] == "type"
                        else (name_value[0], name_value[1])
                        for name_value in iteritems
                    ]
            return iteritems

        # N.B.: Does not use Python 3 dict view semantics
        items = iteritems

        # endregion

    # endregion
