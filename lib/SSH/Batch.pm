package SSH::Batch;

use strict;
use warnings;

our $VERSION = '0.001';

1;
__END__

=head1 NAME

SSH::Batch - Perl module for cluster operations based on Net::OpenSSH

=head1 DESCRIPTION

The following scripts are provided:

* fornodes

    $ cat > ~/.fornodesrc
    ps=blah.ps.com bloo.ps.com boo[2-25,26-70].ps.com
    as=ws[1101-1105].as.com
    ^D
    $ fornodes 'api[02-10].foo.bar.com' 'boo*.ps.com'
    $ fornodes '{ps} + {as} - ws1104.as.com'

* atnodes

    $ atnodes $'ps -fe|grep httpd' 'ws[1101-1105].as.com'

* tonodes

    $ tonodes /tmp/*.inst -- '{as}:/tmp/'
    $ tonodes /tmp/*.inst -- 'ws1105*:/tmp/'

=head1 COPYRIGHT AND LICENSE

This module as well as its programs are licensed under the BSD License.

Copyright (c) 2009, Yahoo! China EEEE Works, Alibaba Inc. All rights reserved.
Copyright (C) 2009, Agent Zhang (agentzh).

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

=over

=item *

Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

=item *

Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

=item *

Neither the name of the Yahoo! China EEEE Works, Alibaba Inc. nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

=back

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
