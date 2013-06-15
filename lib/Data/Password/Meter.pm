package Data::Password::Meter;
use strict;
use warnings;


our $VERSION = 0.01;


# Constructor
sub new {
  my $class = shift;

  # Accept threshold parameter
  my $threshold = $_[0] && $_[0] =~ /^\d+$/ ? $_[0] : 25;
  bless [ $threshold, 0 ], $class;
};


# Error string
sub errstr {
  my $self = shift;
  return '' unless $self->[2];

  # Control systems
  if ($self->[2] eq 'control symbols') {
    return 'Passwords are not allowed to contain control sequences';
  }

  # Only repeating characters
  elsif ($self->[2] eq 'repeating character') {
    return 'Passwords are not allowed to consist of repeating characters only';
  }

  # No password is given
  elsif ($self->[2] eq 'no password') {
    return 'There is no password given'
  }

  # Some errors
  else {
    my $str = 'The password ';

    # Reformat error strings
    # too short - no special characters - no combinations
    $str .= join '; ', @$self[2 .. $#{$self}];
    $str =~ s/; ([^;]+?)$/ and $1/ if @$self > 3;
    $str =~ tr/;/,/;

    return $str;
  };
};


# Score
sub score {
  shift->[1];
};


# Threshold
sub threshold {
  my $self = shift;
  return $self->[0] unless $_[0];
  $self->[0] = shift if $_[0] =~ /^\d+$/;
};


# Check the strength of the password
sub strong {
  my ($self, $pwd) = @_;

  # Initialize object
  @$self = ($self->threshold // 25, 0);

  # No password is too weak
  unless ($pwd) {
    $self->[2] = 'no password';
    return;
  };

  # Control characters
  if ($pwd =~ /[\n\t]/) {
    $self->[2] = 'control symbols';
    return;
  };

  # Only one repeating character
  if ($pwd =~ /^(.)\1*$/) {
    $self->[2] = 'repeating character';
    return;
  };

  my $score = 0;

  # Based on passwordmeter by Steve Moitozo -- geekwisdom.com

  # Length
  my $pwd_l = length $pwd;
  if ($pwd_l < 5) {
    # Less than 5 characters
    $score += 3;
  }
  elsif ($pwd_l > 4 && $pwd_l < 8) {
    # More than 4 characters
    $score += 6;
  }
  elsif ($pwd_l > 7 && $pwd_l < 16) {
    # More than 7 characters
    $score += 12;
  }
  elsif ($pwd_l > 15) {
    # More than 15 characters
    $score += 18;
  };

  if ($pwd_l > 8) {
    # + 2 for every character above 8
    $score += (($pwd_l - 8) * 2);
  }

  # Password is too short
  else {
    push @$self, 'is too short';
  };

  # Letters
  if ($pwd =~ /[a-z]/) {
    # At least one lower case character
    $score++;
  };

  if ($pwd =~ /[A-Z]/) {
    # At least one upper case character
    $score += 5;
  };

  # Numbers
  if ($pwd =~ /\d/) {
    # At least one number
    $score += 5;

    if ($pwd =~ /(?:.*\d){3}/) {
      # At least three numbers
      $score += 5;
    };
  };

  # Special characters
  if ($pwd =~ /[^a-zA-Z0-9]/) {
    # At least one special character
    $score += 5;

    if ($pwd =~ /(?:.*[^a-zA-Z0-9]){2}/) {
      # At least two special characters
      $score += 5;
    };
  }
  else {
    push @$self, 'should contain special characters';
  };

  # Scoring is not enough to succeed
  unless ($score > ($self->threshold - 6)) {
    $self->[1] = $score;
    return;
  };

  # Combos
  if ($pwd =~ /(?:[a-z].*[A-Z])|(?:[A-Z].*[a-z])/) {
    # At least one combination of upper and lower case characters
    $score += 2;
  };

  if ($pwd =~ /(?:[a-zA-Z].*\d)|(?:\d.*[a-zA-Z])/) {
    # At least one combination of letters and numbers
    $score += 2
  };

  if ($pwd =~ /(?:[a-zA-Z0-9].*[^a-zA-Z0-9])|(?:[^a-zA-Z0-9].*[a-zA-Z0-9])/) {
    # At least one combination of letters, numbers and special characters
    $score += 2;
  };

  push @$self, 'should contain combinations of letters, ' .
               'numbers and special characters';

  $self->[1] = $score;
  return if $score < $self->threshold;

  @$self = ($self->threshold, $score);
  return 1;
};


1;


__END__


=pod

=head1 NAME

Data::Password::Meter - Check the strength of passwords


=head1 SYNOPSIS

  my $pwdm = Data::Password::Meter->new(28);

  # Check a password
  if ($pwdm->strong('s3cur3-p4ssw0rd')) {
    print "The password is strong enough!\n";
    print 'Scored ' . $pwdm->score . ' points!';
  }
  else {
    warn $pwdm->errstr;
  };


=head1 DESCRIPTION

Check the strength of a password. The scoring is based on
L<Passwordmeter|http://www.geekwisdom.com/js/passwordmeter.js>
by Steve Moitozo.


=head1 ATTRIBUTES

=head2 errstr

  print $pwdm->errstr;

The L<error string|/ERROR STRINGS> of the last failing check.


=head2 score

  print $pwdm->score;

The score of the last check.


=head2 threshold

  print $pwdm->threshold;
  $pwdm->threshold(28);

The scoring threshold,
the determining factor when a password is too weak.
Every password that is below this threshold
is considered weak.
Defaults to a score of C<25>.


=head1 METHODS

=head2 new

  my $pwd = Data::Password::Meter->new(28);

Constructs a new password check object.
Accepts an optional value for the L<threshold|/threshold>.


=head2 strong


  if ($pwdm->strong('mypassword')) {
    print 'This password is strong!';
  }
  else {
    print 'This password is weak!';
  };

Checks a password for strength.
Returns a false value in case the password
is considered to be weak.


=head1 ERROR STRINGS

Possible error strings are:

=over 2

=item *

There is no password given

=item *

Passwords are not allowed to contain control sequences

=item *

Passwords are not allowed to consist of repeating characters only

=item *

The password is too short

=item *

The password should contain special characters

=item *

The password should contain combinations of letters, numbers and special characters

=item *

The password is too short and should contain special characters

=item *

The password is too short and should contain combinations of letters, numbers and special characters

=item *

The password is too short, should contain special characters and should contain combinations of letters, numbers and special characters

=item *

The password should contain special characters and should contain combinations of letters, numbers and special characters

=back


=head1 DEPENDENCIES

No dependencies other than core.


=head1 AVAILABILITY

  https://github.com/Akron/Data-Password-Meter


=head1 COPYRIGHT AND LICENSE

Copyright (C) 2006, Steve Moitozo, (C) 2013, L<Nils Diewald|http://nils-diewald.de>.

Licensed under the MIT License

=cut
