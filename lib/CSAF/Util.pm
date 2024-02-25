package CSAF::Util;

use 5.010001;
use strict;
use warnings;

use Cpanel::JSON::XS;
use Time::Piece;
use File::Basename        qw(dirname);
use File::Spec::Functions qw(catfile);

use Exporter 'import';

our @EXPORT_OK = (qw(
    schema_cache_path resources_path tt_templates_path
    check_datetime tracking_id_to_well_filename
    get_weakness_name collect_product_ids check_purl
    file_read JSON
));

my $PURL_REGEXP = qr{^pkg:[A-Za-z\\.\\-\\+][A-Za-z0-9\\.\\-\\+]*/.+};

sub JSON {
    Cpanel::JSON::XS->new->utf8->canonical->allow_nonref->allow_unknown->allow_blessed->convert_blessed
        ->stringify_infnan->escape_slash->allow_dupkeys->pretty;
}

sub check_purl {
    return (shift =~ /$PURL_REGEXP/);
}

sub get_weakness_name {

    my $weakness = shift;
    return unless $weakness;

    state $weaknesses = {};

    unless (keys %{$weaknesses}) {
        while (my $line = <DATA>) {
            chomp($line);
            my ($cwe_id, $name, $type) = split '\|', $line;
            $weaknesses->{$cwe_id} = $name;
        }
    }

    $weaknesses->{$weakness};

}

sub Time::Piece::TO_JSON {
    shift->datetime;
}


sub schema_cache_path {
    return catfile(resources_path(), 'cache');
}

sub tt_templates_path {
    return catfile(resources_path(), 'template');
}

sub resources_path {
    return catfile(dirname(__FILE__), 'resources');
}

sub check_datetime {

    my $datetime = shift;
    return unless $datetime;

    return $datetime if ($datetime->isa('Time::Piece'));

    return Time::Piece->new($datetime) if ($datetime =~ /^([0-9]+)$/);
    return Time::Piece->new            if ($datetime eq 'now');

    return Time::Piece->strptime($1, '%Y-%m-%dT%H:%M:%S') if ($datetime =~ /(\d{4}-\d{2}-\d{2}[T]\d{2}:\d{2}:\d{2})/);
    return Time::Piece->strptime($1, '%Y-%m-%d %H:%M:%S') if ($datetime =~ /(\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2})/);
    return Time::Piece->strptime($1, '%Y-%m-%d')          if ($datetime =~ /(\d{4}-\d{2}-\d{2})/);

}

sub tracking_id_to_well_filename {

    my $id = shift;

    $id = lc $id;
    $id =~ s/[^+\-a-z0-9]+/_/;    # Rif. 5.1 (Additional Conventions - Filename)

    return "$id.json";

}

sub collect_product_ids {

    my $item        = shift;
    my @product_ids = ();

    my $ref_item = ref($item);

    if ($ref_item =~ /Branch$/) {

        if ($item->has_product) {
            push @product_ids, $item->product->product_id;
        }

        foreach (@{$item->branches->items}) {
            push @product_ids, collect_product_ids($_);
        }

    }

    if ($ref_item =~ /FullProductName$/) {
        push @product_ids, $item->product_id;
    }

    return @product_ids;

}


sub file_read {

    my ($file) = @_;

    my $content = do {
        open(my $fh, '<', $file) or Carp::croak qq{Failed to read file: $!};
        local $/ = undef;
        <$fh>;
    };

    return $content;

}


1;

__DATA__
CWE-1|DEPRECATED: Location|category
CWE-2|7PK - Environment|category
CWE-3|DEPRECATED: Technology-specific Environment Issues|category
CWE-4|DEPRECATED: J2EE Environment Issues|category
CWE-5|J2EE Misconfiguration: Data Transmission Without Encryption|weakness
CWE-6|J2EE Misconfiguration: Insufficient Session-ID Length|weakness
CWE-7|J2EE Misconfiguration: Missing Custom Error Page|weakness
CWE-8|J2EE Misconfiguration: Entity Bean Declared Remote|weakness
CWE-9|J2EE Misconfiguration: Weak Access Permissions for EJB Methods|weakness
CWE-10|DEPRECATED: ASP.NET Environment Issues|category
CWE-11|ASP.NET Misconfiguration: Creating Debug Binary|weakness
CWE-12|ASP.NET Misconfiguration: Missing Custom Error Page|weakness
CWE-13|ASP.NET Misconfiguration: Password in Configuration File|weakness
CWE-14|Compiler Removal of Code to Clear Buffers|weakness
CWE-15|External Control of System or Configuration Setting|weakness
CWE-16|Configuration|category
CWE-17|DEPRECATED: Code|category
CWE-18|DEPRECATED: Source Code|category
CWE-19|Data Processing Errors|category
CWE-20|Improper Input Validation|weakness
CWE-21|DEPRECATED: Pathname Traversal and Equivalence Errors|category
CWE-22|Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')|weakness
CWE-23|Relative Path Traversal|weakness
CWE-24|Path Traversal: '../filedir'|weakness
CWE-25|Path Traversal: '/../filedir'|weakness
CWE-26|Path Traversal: '/dir/../filename'|weakness
CWE-27|Path Traversal: 'dir/../../filename'|weakness
CWE-28|Path Traversal: '..\filedir'|weakness
CWE-29|Path Traversal: '\..\filename'|weakness
CWE-30|Path Traversal: '\dir\..\filename'|weakness
CWE-31|Path Traversal: 'dir\..\..\filename'|weakness
CWE-32|Path Traversal: '...' (Triple Dot)|weakness
CWE-33|Path Traversal: '....' (Multiple Dot)|weakness
CWE-34|Path Traversal: '....//'|weakness
CWE-35|Path Traversal: '.../...//'|weakness
CWE-36|Absolute Path Traversal|weakness
CWE-37|Path Traversal: '/absolute/pathname/here'|weakness
CWE-38|Path Traversal: '\absolute\pathname\here'|weakness
CWE-39|Path Traversal: 'C:dirname'|weakness
CWE-40|Path Traversal: '\\UNC\share\name\' (Windows UNC Share)|weakness
CWE-41|Improper Resolution of Path Equivalence|weakness
CWE-42|Path Equivalence: 'filename.' (Trailing Dot)|weakness
CWE-43|Path Equivalence: 'filename....' (Multiple Trailing Dot)|weakness
CWE-44|Path Equivalence: 'file.name' (Internal Dot)|weakness
CWE-45|Path Equivalence: 'file...name' (Multiple Internal Dot)|weakness
CWE-46|Path Equivalence: 'filename ' (Trailing Space)|weakness
CWE-47|Path Equivalence: ' filename' (Leading Space)|weakness
CWE-48|Path Equivalence: 'file name' (Internal Whitespace)|weakness
CWE-49|Path Equivalence: 'filename/' (Trailing Slash)|weakness
CWE-50|Path Equivalence: '//multiple/leading/slash'|weakness
CWE-51|Path Equivalence: '/multiple//internal/slash'|weakness
CWE-52|Path Equivalence: '/multiple/trailing/slash//'|weakness
CWE-53|Path Equivalence: '\multiple\\internal\backslash'|weakness
CWE-54|Path Equivalence: 'filedir\' (Trailing Backslash)|weakness
CWE-55|Path Equivalence: '/./' (Single Dot Directory)|weakness
CWE-56|Path Equivalence: 'filedir*' (Wildcard)|weakness
CWE-57|Path Equivalence: 'fakedir/../realdir/filename'|weakness
CWE-58|Path Equivalence: Windows 8.3 Filename|weakness
CWE-59|Improper Link Resolution Before File Access ('Link Following')|weakness
CWE-60|DEPRECATED: UNIX Path Link Problems|category
CWE-61|UNIX Symbolic Link (Symlink) Following|weakness
CWE-62|UNIX Hard Link|weakness
CWE-63|DEPRECATED: Windows Path Link Problems|category
CWE-64|Windows Shortcut Following (.LNK)|weakness
CWE-65|Windows Hard Link|weakness
CWE-66|Improper Handling of File Names that Identify Virtual Resources|weakness
CWE-67|Improper Handling of Windows Device Names|weakness
CWE-68|DEPRECATED: Windows Virtual File Problems|category
CWE-69|Improper Handling of Windows ::DATA Alternate Data Stream|weakness
CWE-70|DEPRECATED: Mac Virtual File Problems|category
CWE-71|DEPRECATED: Apple '.DS_Store'|weakness
CWE-72|Improper Handling of Apple HFS+ Alternate Data Stream Path|weakness
CWE-73|External Control of File Name or Path|weakness
CWE-74|Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection')|weakness
CWE-75|Failure to Sanitize Special Elements into a Different Plane (Special Element Injection)|weakness
CWE-76|Improper Neutralization of Equivalent Special Elements|weakness
CWE-77|Improper Neutralization of Special Elements used in a Command ('Command Injection')|weakness
CWE-78|Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')|weakness
CWE-79|Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')|weakness
CWE-80|Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)|weakness
CWE-81|Improper Neutralization of Script in an Error Message Web Page|weakness
CWE-82|Improper Neutralization of Script in Attributes of IMG Tags in a Web Page|weakness
CWE-83|Improper Neutralization of Script in Attributes in a Web Page|weakness
CWE-84|Improper Neutralization of Encoded URI Schemes in a Web Page|weakness
CWE-85|Doubled Character XSS Manipulations|weakness
CWE-86|Improper Neutralization of Invalid Characters in Identifiers in Web Pages|weakness
CWE-87|Improper Neutralization of Alternate XSS Syntax|weakness
CWE-88|Improper Neutralization of Argument Delimiters in a Command ('Argument Injection')|weakness
CWE-89|Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')|weakness
CWE-90|Improper Neutralization of Special Elements used in an LDAP Query ('LDAP Injection')|weakness
CWE-91|XML Injection (aka Blind XPath Injection)|weakness
CWE-92|DEPRECATED: Improper Sanitization of Custom Special Characters|weakness
CWE-93|Improper Neutralization of CRLF Sequences ('CRLF Injection')|weakness
CWE-94|Improper Control of Generation of Code ('Code Injection')|weakness
CWE-95|Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')|weakness
CWE-96|Improper Neutralization of Directives in Statically Saved Code ('Static Code Injection')|weakness
CWE-97|Improper Neutralization of Server-Side Includes (SSI) Within a Web Page|weakness
CWE-98|Improper Control of Filename for Include/Require Statement in PHP Program ('PHP Remote File Inclusion')|weakness
CWE-99|Improper Control of Resource Identifiers ('Resource Injection')|weakness
CWE-100|DEPRECATED: Technology-Specific Input Validation Problems|category
CWE-101|DEPRECATED: Struts Validation Problems|category
CWE-102|Struts: Duplicate Validation Forms|weakness
CWE-103|Struts: Incomplete validate() Method Definition|weakness
CWE-104|Struts: Form Bean Does Not Extend Validation Class|weakness
CWE-105|Struts: Form Field Without Validator|weakness
CWE-106|Struts: Plug-in Framework not in Use|weakness
CWE-107|Struts: Unused Validation Form|weakness
CWE-108|Struts: Unvalidated Action Form|weakness
CWE-109|Struts: Validator Turned Off|weakness
CWE-110|Struts: Validator Without Form Field|weakness
CWE-111|Direct Use of Unsafe JNI|weakness
CWE-112|Missing XML Validation|weakness
CWE-113|Improper Neutralization of CRLF Sequences in HTTP Headers ('HTTP Request/Response Splitting')|weakness
CWE-114|Process Control|weakness
CWE-115|Misinterpretation of Input|weakness
CWE-116|Improper Encoding or Escaping of Output|weakness
CWE-117|Improper Output Neutralization for Logs|weakness
CWE-118|Incorrect Access of Indexable Resource ('Range Error')|weakness
CWE-119|Improper Restriction of Operations within the Bounds of a Memory Buffer|weakness
CWE-120|Buffer Copy without Checking Size of Input ('Classic Buffer Overflow')|weakness
CWE-121|Stack-based Buffer Overflow|weakness
CWE-122|Heap-based Buffer Overflow|weakness
CWE-123|Write-what-where Condition|weakness
CWE-124|Buffer Underwrite ('Buffer Underflow')|weakness
CWE-125|Out-of-bounds Read|weakness
CWE-126|Buffer Over-read|weakness
CWE-127|Buffer Under-read|weakness
CWE-128|Wrap-around Error|weakness
CWE-129|Improper Validation of Array Index|weakness
CWE-130|Improper Handling of Length Parameter Inconsistency|weakness
CWE-131|Incorrect Calculation of Buffer Size|weakness
CWE-132|DEPRECATED: Miscalculated Null Termination|weakness
CWE-133|String Errors|category
CWE-134|Use of Externally-Controlled Format String|weakness
CWE-135|Incorrect Calculation of Multi-Byte String Length|weakness
CWE-136|Type Errors|category
CWE-137|Data Neutralization Issues|category
CWE-138|Improper Neutralization of Special Elements|weakness
CWE-139|DEPRECATED: General Special Element Problems|category
CWE-140|Improper Neutralization of Delimiters|weakness
CWE-141|Improper Neutralization of Parameter/Argument Delimiters|weakness
CWE-142|Improper Neutralization of Value Delimiters|weakness
CWE-143|Improper Neutralization of Record Delimiters|weakness
CWE-144|Improper Neutralization of Line Delimiters|weakness
CWE-145|Improper Neutralization of Section Delimiters|weakness
CWE-146|Improper Neutralization of Expression/Command Delimiters|weakness
CWE-147|Improper Neutralization of Input Terminators|weakness
CWE-148|Improper Neutralization of Input Leaders|weakness
CWE-149|Improper Neutralization of Quoting Syntax|weakness
CWE-150|Improper Neutralization of Escape, Meta, or Control Sequences|weakness
CWE-151|Improper Neutralization of Comment Delimiters|weakness
CWE-152|Improper Neutralization of Macro Symbols|weakness
CWE-153|Improper Neutralization of Substitution Characters|weakness
CWE-154|Improper Neutralization of Variable Name Delimiters|weakness
CWE-155|Improper Neutralization of Wildcards or Matching Symbols|weakness
CWE-156|Improper Neutralization of Whitespace|weakness
CWE-157|Failure to Sanitize Paired Delimiters|weakness
CWE-158|Improper Neutralization of Null Byte or NUL Character|weakness
CWE-159|Improper Handling of Invalid Use of Special Elements|weakness
CWE-160|Improper Neutralization of Leading Special Elements|weakness
CWE-161|Improper Neutralization of Multiple Leading Special Elements|weakness
CWE-162|Improper Neutralization of Trailing Special Elements|weakness
CWE-163|Improper Neutralization of Multiple Trailing Special Elements|weakness
CWE-164|Improper Neutralization of Internal Special Elements|weakness
CWE-165|Improper Neutralization of Multiple Internal Special Elements|weakness
CWE-166|Improper Handling of Missing Special Element|weakness
CWE-167|Improper Handling of Additional Special Element|weakness
CWE-168|Improper Handling of Inconsistent Special Elements|weakness
CWE-169|DEPRECATED: Technology-Specific Special Elements|category
CWE-170|Improper Null Termination|weakness
CWE-171|DEPRECATED: Cleansing, Canonicalization, and Comparison Errors|category
CWE-172|Encoding Error|weakness
CWE-173|Improper Handling of Alternate Encoding|weakness
CWE-174|Double Decoding of the Same Data|weakness
CWE-175|Improper Handling of Mixed Encoding|weakness
CWE-176|Improper Handling of Unicode Encoding|weakness
CWE-177|Improper Handling of URL Encoding (Hex Encoding)|weakness
CWE-178|Improper Handling of Case Sensitivity|weakness
CWE-179|Incorrect Behavior Order: Early Validation|weakness
CWE-180|Incorrect Behavior Order: Validate Before Canonicalize|weakness
CWE-181|Incorrect Behavior Order: Validate Before Filter|weakness
CWE-182|Collapse of Data into Unsafe Value|weakness
CWE-183|Permissive List of Allowed Inputs|weakness
CWE-184|Incomplete List of Disallowed Inputs|weakness
CWE-185|Incorrect Regular Expression|weakness
CWE-186|Overly Restrictive Regular Expression|weakness
CWE-187|Partial String Comparison|weakness
CWE-188|Reliance on Data/Memory Layout|weakness
CWE-189|Numeric Errors|category
CWE-190|Integer Overflow or Wraparound|weakness
CWE-191|Integer Underflow (Wrap or Wraparound)|weakness
CWE-192|Integer Coercion Error|weakness
CWE-193|Off-by-one Error|weakness
CWE-194|Unexpected Sign Extension|weakness
CWE-195|Signed to Unsigned Conversion Error|weakness
CWE-196|Unsigned to Signed Conversion Error|weakness
CWE-197|Numeric Truncation Error|weakness
CWE-198|Use of Incorrect Byte Ordering|weakness
CWE-199|Information Management Errors|category
CWE-200|Exposure of Sensitive Information to an Unauthorized Actor|weakness
CWE-201|Insertion of Sensitive Information Into Sent Data|weakness
CWE-202|Exposure of Sensitive Information Through Data Queries|weakness
CWE-203|Observable Discrepancy|weakness
CWE-204|Observable Response Discrepancy|weakness
CWE-205|Observable Behavioral Discrepancy|weakness
CWE-206|Observable Internal Behavioral Discrepancy|weakness
CWE-207|Observable Behavioral Discrepancy With Equivalent Products|weakness
CWE-208|Observable Timing Discrepancy|weakness
CWE-209|Generation of Error Message Containing Sensitive Information|weakness
CWE-210|Self-generated Error Message Containing Sensitive Information|weakness
CWE-211|Externally-Generated Error Message Containing Sensitive Information|weakness
CWE-212|Improper Removal of Sensitive Information Before Storage or Transfer|weakness
CWE-213|Exposure of Sensitive Information Due to Incompatible Policies|weakness
CWE-214|Invocation of Process Using Visible Sensitive Information|weakness
CWE-215|Insertion of Sensitive Information Into Debugging Code|weakness
CWE-216|DEPRECATED: Containment Errors (Container Errors)|weakness
CWE-217|DEPRECATED: Failure to Protect Stored Data from Modification|weakness
CWE-218|DEPRECATED: Failure to provide confidentiality for stored data|weakness
CWE-219|Storage of File with Sensitive Data Under Web Root|weakness
CWE-220|Storage of File With Sensitive Data Under FTP Root|weakness
CWE-221|Information Loss or Omission|weakness
CWE-222|Truncation of Security-relevant Information|weakness
CWE-223|Omission of Security-relevant Information|weakness
CWE-224|Obscured Security-relevant Information by Alternate Name|weakness
CWE-225|DEPRECATED: General Information Management Problems|weakness
CWE-226|Sensitive Information in Resource Not Removed Before Reuse|weakness
CWE-227|7PK - API Abuse|category
CWE-228|Improper Handling of Syntactically Invalid Structure|weakness
CWE-229|Improper Handling of Values|weakness
CWE-230|Improper Handling of Missing Values|weakness
CWE-231|Improper Handling of Extra Values|weakness
CWE-232|Improper Handling of Undefined Values|weakness
CWE-233|Improper Handling of Parameters|weakness
CWE-234|Failure to Handle Missing Parameter|weakness
CWE-235|Improper Handling of Extra Parameters|weakness
CWE-236|Improper Handling of Undefined Parameters|weakness
CWE-237|Improper Handling of Structural Elements|weakness
CWE-238|Improper Handling of Incomplete Structural Elements|weakness
CWE-239|Failure to Handle Incomplete Element|weakness
CWE-240|Improper Handling of Inconsistent Structural Elements|weakness
CWE-241|Improper Handling of Unexpected Data Type|weakness
CWE-242|Use of Inherently Dangerous Function|weakness
CWE-243|Creation of chroot Jail Without Changing Working Directory|weakness
CWE-244|Improper Clearing of Heap Memory Before Release ('Heap Inspection')|weakness
CWE-245|J2EE Bad Practices: Direct Management of Connections|weakness
CWE-246|J2EE Bad Practices: Direct Use of Sockets|weakness
CWE-247|DEPRECATED: Reliance on DNS Lookups in a Security Decision|weakness
CWE-248|Uncaught Exception|weakness
CWE-249|DEPRECATED: Often Misused: Path Manipulation|weakness
CWE-250|Execution with Unnecessary Privileges|weakness
CWE-251|Often Misused: String Management|category
CWE-252|Unchecked Return Value|weakness
CWE-253|Incorrect Check of Function Return Value|weakness
CWE-254|7PK - Security Features|category
CWE-255|Credentials Management Errors|category
CWE-256|Plaintext Storage of a Password|weakness
CWE-257|Storing Passwords in a Recoverable Format|weakness
CWE-258|Empty Password in Configuration File|weakness
CWE-259|Use of Hard-coded Password|weakness
CWE-260|Password in Configuration File|weakness
CWE-261|Weak Encoding for Password|weakness
CWE-262|Not Using Password Aging|weakness
CWE-263|Password Aging with Long Expiration|weakness
CWE-264|Permissions, Privileges, and Access Controls|category
CWE-265|Privilege Issues|category
CWE-266|Incorrect Privilege Assignment|weakness
CWE-267|Privilege Defined With Unsafe Actions|weakness
CWE-268|Privilege Chaining|weakness
CWE-269|Improper Privilege Management|weakness
CWE-270|Privilege Context Switching Error|weakness
CWE-271|Privilege Dropping / Lowering Errors|weakness
CWE-272|Least Privilege Violation|weakness
CWE-273|Improper Check for Dropped Privileges|weakness
CWE-274|Improper Handling of Insufficient Privileges|weakness
CWE-275|Permission Issues|category
CWE-276|Incorrect Default Permissions|weakness
CWE-277|Insecure Inherited Permissions|weakness
CWE-278|Insecure Preserved Inherited Permissions|weakness
CWE-279|Incorrect Execution-Assigned Permissions|weakness
CWE-280|Improper Handling of Insufficient Permissions or Privileges |weakness
CWE-281|Improper Preservation of Permissions|weakness
CWE-282|Improper Ownership Management|weakness
CWE-283|Unverified Ownership|weakness
CWE-284|Improper Access Control|weakness
CWE-285|Improper Authorization|weakness
CWE-286|Incorrect User Management|weakness
CWE-287|Improper Authentication|weakness
CWE-288|Authentication Bypass Using an Alternate Path or Channel|weakness
CWE-289|Authentication Bypass by Alternate Name|weakness
CWE-290|Authentication Bypass by Spoofing|weakness
CWE-291|Reliance on IP Address for Authentication|weakness
CWE-292|DEPRECATED: Trusting Self-reported DNS Name|weakness
CWE-293|Using Referer Field for Authentication|weakness
CWE-294|Authentication Bypass by Capture-replay|weakness
CWE-295|Improper Certificate Validation|weakness
CWE-296|Improper Following of a Certificate's Chain of Trust|weakness
CWE-297|Improper Validation of Certificate with Host Mismatch|weakness
CWE-298|Improper Validation of Certificate Expiration|weakness
CWE-299|Improper Check for Certificate Revocation|weakness
CWE-300|Channel Accessible by Non-Endpoint|weakness
CWE-301|Reflection Attack in an Authentication Protocol|weakness
CWE-302|Authentication Bypass by Assumed-Immutable Data|weakness
CWE-303|Incorrect Implementation of Authentication Algorithm|weakness
CWE-304|Missing Critical Step in Authentication|weakness
CWE-305|Authentication Bypass by Primary Weakness|weakness
CWE-306|Missing Authentication for Critical Function|weakness
CWE-307|Improper Restriction of Excessive Authentication Attempts|weakness
CWE-308|Use of Single-factor Authentication|weakness
CWE-309|Use of Password System for Primary Authentication|weakness
CWE-310|Cryptographic Issues|category
CWE-311|Missing Encryption of Sensitive Data|weakness
CWE-312|Cleartext Storage of Sensitive Information|weakness
CWE-313|Cleartext Storage in a File or on Disk|weakness
CWE-314|Cleartext Storage in the Registry|weakness
CWE-315|Cleartext Storage of Sensitive Information in a Cookie|weakness
CWE-316|Cleartext Storage of Sensitive Information in Memory|weakness
CWE-317|Cleartext Storage of Sensitive Information in GUI|weakness
CWE-318|Cleartext Storage of Sensitive Information in Executable|weakness
CWE-319|Cleartext Transmission of Sensitive Information|weakness
CWE-320|Key Management Errors|category
CWE-321|Use of Hard-coded Cryptographic Key|weakness
CWE-322|Key Exchange without Entity Authentication|weakness
CWE-323|Reusing a Nonce, Key Pair in Encryption|weakness
CWE-324|Use of a Key Past its Expiration Date|weakness
CWE-325|Missing Cryptographic Step|weakness
CWE-326|Inadequate Encryption Strength|weakness
CWE-327|Use of a Broken or Risky Cryptographic Algorithm|weakness
CWE-328|Use of Weak Hash|weakness
CWE-329|Generation of Predictable IV with CBC Mode|weakness
CWE-330|Use of Insufficiently Random Values|weakness
CWE-331|Insufficient Entropy|weakness
CWE-332|Insufficient Entropy in PRNG|weakness
CWE-333|Improper Handling of Insufficient Entropy in TRNG|weakness
CWE-334|Small Space of Random Values|weakness
CWE-335|Incorrect Usage of Seeds in Pseudo-Random Number Generator (PRNG)|weakness
CWE-336|Same Seed in Pseudo-Random Number Generator (PRNG)|weakness
CWE-337|Predictable Seed in Pseudo-Random Number Generator (PRNG)|weakness
CWE-338|Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)|weakness
CWE-339|Small Seed Space in PRNG|weakness
CWE-340|Generation of Predictable Numbers or Identifiers|weakness
CWE-341|Predictable from Observable State|weakness
CWE-342|Predictable Exact Value from Previous Values|weakness
CWE-343|Predictable Value Range from Previous Values|weakness
CWE-344|Use of Invariant Value in Dynamically Changing Context|weakness
CWE-345|Insufficient Verification of Data Authenticity|weakness
CWE-346|Origin Validation Error|weakness
CWE-347|Improper Verification of Cryptographic Signature|weakness
CWE-348|Use of Less Trusted Source|weakness
CWE-349|Acceptance of Extraneous Untrusted Data With Trusted Data|weakness
CWE-350|Reliance on Reverse DNS Resolution for a Security-Critical Action|weakness
CWE-351|Insufficient Type Distinction|weakness
CWE-352|Cross-Site Request Forgery (CSRF)|weakness
CWE-353|Missing Support for Integrity Check|weakness
CWE-354|Improper Validation of Integrity Check Value|weakness
CWE-355|User Interface Security Issues|category
CWE-356|Product UI does not Warn User of Unsafe Actions|weakness
CWE-357|Insufficient UI Warning of Dangerous Operations|weakness
CWE-358|Improperly Implemented Security Check for Standard|weakness
CWE-359|Exposure of Private Personal Information to an Unauthorized Actor|weakness
CWE-360|Trust of System Event Data|weakness
CWE-361|7PK - Time and State|category
CWE-362|Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')|weakness
CWE-363|Race Condition Enabling Link Following|weakness
CWE-364|Signal Handler Race Condition|weakness
CWE-365|DEPRECATED: Race Condition in Switch|weakness
CWE-366|Race Condition within a Thread|weakness
CWE-367|Time-of-check Time-of-use (TOCTOU) Race Condition|weakness
CWE-368|Context Switching Race Condition|weakness
CWE-369|Divide By Zero|weakness
CWE-370|Missing Check for Certificate Revocation after Initial Check|weakness
CWE-371|State Issues|category
CWE-372|Incomplete Internal State Distinction|weakness
CWE-373|DEPRECATED: State Synchronization Error|weakness
CWE-374|Passing Mutable Objects to an Untrusted Method|weakness
CWE-375|Returning a Mutable Object to an Untrusted Caller|weakness
CWE-376|DEPRECATED: Temporary File Issues|category
CWE-377|Insecure Temporary File|weakness
CWE-378|Creation of Temporary File With Insecure Permissions|weakness
CWE-379|Creation of Temporary File in Directory with Insecure Permissions|weakness
CWE-380|DEPRECATED: Technology-Specific Time and State Issues|category
CWE-381|DEPRECATED: J2EE Time and State Issues|category
CWE-382|J2EE Bad Practices: Use of System.exit()|weakness
CWE-383|J2EE Bad Practices: Direct Use of Threads|weakness
CWE-384|Session Fixation|weakness
CWE-385|Covert Timing Channel|weakness
CWE-386|Symbolic Name not Mapping to Correct Object|weakness
CWE-387|Signal Errors|category
CWE-388|7PK - Errors|category
CWE-389|Error Conditions, Return Values, Status Codes|category
CWE-390|Detection of Error Condition Without Action|weakness
CWE-391|Unchecked Error Condition|weakness
CWE-392|Missing Report of Error Condition|weakness
CWE-393|Return of Wrong Status Code|weakness
CWE-394|Unexpected Status Code or Return Value|weakness
CWE-395|Use of NullPointerException Catch to Detect NULL Pointer Dereference|weakness
CWE-396|Declaration of Catch for Generic Exception|weakness
CWE-397|Declaration of Throws for Generic Exception|weakness
CWE-398|7PK - Code Quality|category
CWE-399|Resource Management Errors|category
CWE-400|Uncontrolled Resource Consumption|weakness
CWE-401|Missing Release of Memory after Effective Lifetime|weakness
CWE-402|Transmission of Private Resources into a New Sphere ('Resource Leak')|weakness
CWE-403|Exposure of File Descriptor to Unintended Control Sphere ('File Descriptor Leak')|weakness
CWE-404|Improper Resource Shutdown or Release|weakness
CWE-405|Asymmetric Resource Consumption (Amplification)|weakness
CWE-406|Insufficient Control of Network Message Volume (Network Amplification)|weakness
CWE-407|Inefficient Algorithmic Complexity|weakness
CWE-408|Incorrect Behavior Order: Early Amplification|weakness
CWE-409|Improper Handling of Highly Compressed Data (Data Amplification)|weakness
CWE-410|Insufficient Resource Pool|weakness
CWE-411|Resource Locking Problems|category
CWE-412|Unrestricted Externally Accessible Lock|weakness
CWE-413|Improper Resource Locking|weakness
CWE-414|Missing Lock Check|weakness
CWE-415|Double Free|weakness
CWE-416|Use After Free|weakness
CWE-417|Communication Channel Errors|category
CWE-418|DEPRECATED: Channel Errors|category
CWE-419|Unprotected Primary Channel|weakness
CWE-420|Unprotected Alternate Channel|weakness
CWE-421|Race Condition During Access to Alternate Channel|weakness
CWE-422|Unprotected Windows Messaging Channel ('Shatter')|weakness
CWE-423|DEPRECATED: Proxied Trusted Channel|weakness
CWE-424|Improper Protection of Alternate Path|weakness
CWE-425|Direct Request ('Forced Browsing')|weakness
CWE-426|Untrusted Search Path|weakness
CWE-427|Uncontrolled Search Path Element|weakness
CWE-428|Unquoted Search Path or Element|weakness
CWE-429|Handler Errors|category
CWE-430|Deployment of Wrong Handler|weakness
CWE-431|Missing Handler|weakness
CWE-432|Dangerous Signal Handler not Disabled During Sensitive Operations|weakness
CWE-433|Unparsed Raw Web Content Delivery|weakness
CWE-434|Unrestricted Upload of File with Dangerous Type|weakness
CWE-435|Improper Interaction Between Multiple Correctly-Behaving Entities|weakness
CWE-436|Interpretation Conflict|weakness
CWE-437|Incomplete Model of Endpoint Features|weakness
CWE-438|Behavioral Problems|category
CWE-439|Behavioral Change in New Version or Environment|weakness
CWE-440|Expected Behavior Violation|weakness
CWE-441|Unintended Proxy or Intermediary ('Confused Deputy')|weakness
CWE-442|DEPRECATED: Web Problems|category
CWE-443|DEPRECATED: HTTP response splitting|weakness
CWE-444|Inconsistent Interpretation of HTTP Requests ('HTTP Request/Response Smuggling')|weakness
CWE-445|DEPRECATED: User Interface Errors|category
CWE-446|UI Discrepancy for Security Feature|weakness
CWE-447|Unimplemented or Unsupported Feature in UI|weakness
CWE-448|Obsolete Feature in UI|weakness
CWE-449|The UI Performs the Wrong Action|weakness
CWE-450|Multiple Interpretations of UI Input|weakness
CWE-451|User Interface (UI) Misrepresentation of Critical Information|weakness
CWE-452|Initialization and Cleanup Errors|category
CWE-453|Insecure Default Variable Initialization|weakness
CWE-454|External Initialization of Trusted Variables or Data Stores|weakness
CWE-455|Non-exit on Failed Initialization|weakness
CWE-456|Missing Initialization of a Variable|weakness
CWE-457|Use of Uninitialized Variable|weakness
CWE-458|DEPRECATED: Incorrect Initialization|weakness
CWE-459|Incomplete Cleanup|weakness
CWE-460|Improper Cleanup on Thrown Exception|weakness
CWE-461|DEPRECATED: Data Structure Issues|category
CWE-462|Duplicate Key in Associative List (Alist)|weakness
CWE-463|Deletion of Data Structure Sentinel|weakness
CWE-464|Addition of Data Structure Sentinel|weakness
CWE-465|Pointer Issues|category
CWE-466|Return of Pointer Value Outside of Expected Range|weakness
CWE-467|Use of sizeof() on a Pointer Type|weakness
CWE-468|Incorrect Pointer Scaling|weakness
CWE-469|Use of Pointer Subtraction to Determine Size|weakness
CWE-470|Use of Externally-Controlled Input to Select Classes or Code ('Unsafe Reflection')|weakness
CWE-471|Modification of Assumed-Immutable Data (MAID)|weakness
CWE-472|External Control of Assumed-Immutable Web Parameter|weakness
CWE-473|PHP External Variable Modification|weakness
CWE-474|Use of Function with Inconsistent Implementations|weakness
CWE-475|Undefined Behavior for Input to API|weakness
CWE-476|NULL Pointer Dereference|weakness
CWE-477|Use of Obsolete Function|weakness
CWE-478|Missing Default Case in Multiple Condition Expression|weakness
CWE-479|Signal Handler Use of a Non-reentrant Function|weakness
CWE-480|Use of Incorrect Operator|weakness
CWE-481|Assigning instead of Comparing|weakness
CWE-482|Comparing instead of Assigning|weakness
CWE-483|Incorrect Block Delimitation|weakness
CWE-484|Omitted Break Statement in Switch|weakness
CWE-485|7PK - Encapsulation|category
CWE-486|Comparison of Classes by Name|weakness
CWE-487|Reliance on Package-level Scope|weakness
CWE-488|Exposure of Data Element to Wrong Session|weakness
CWE-489|Active Debug Code|weakness
CWE-490|DEPRECATED: Mobile Code Issues|category
CWE-491|Public cloneable() Method Without Final ('Object Hijack')|weakness
CWE-492|Use of Inner Class Containing Sensitive Data|weakness
CWE-493|Critical Public Variable Without Final Modifier|weakness
CWE-494|Download of Code Without Integrity Check|weakness
CWE-495|Private Data Structure Returned From A Public Method|weakness
CWE-496|Public Data Assigned to Private Array-Typed Field|weakness
CWE-497|Exposure of Sensitive System Information to an Unauthorized Control Sphere|weakness
CWE-498|Cloneable Class Containing Sensitive Information|weakness
CWE-499|Serializable Class Containing Sensitive Data|weakness
CWE-500|Public Static Field Not Marked Final|weakness
CWE-501|Trust Boundary Violation|weakness
CWE-502|Deserialization of Untrusted Data|weakness
CWE-503|DEPRECATED: Byte/Object Code|category
CWE-504|DEPRECATED: Motivation/Intent|category
CWE-505|DEPRECATED: Intentionally Introduced Weakness|category
CWE-506|Embedded Malicious Code|weakness
CWE-507|Trojan Horse|weakness
CWE-508|Non-Replicating Malicious Code|weakness
CWE-509|Replicating Malicious Code (Virus or Worm)|weakness
CWE-510|Trapdoor|weakness
CWE-511|Logic/Time Bomb|weakness
CWE-512|Spyware|weakness
CWE-513|DEPRECATED: Intentionally Introduced Nonmalicious Weakness|category
CWE-514|Covert Channel|weakness
CWE-515|Covert Storage Channel|weakness
CWE-516|DEPRECATED: Covert Timing Channel|weakness
CWE-517|DEPRECATED: Other Intentional, Nonmalicious Weakness|category
CWE-518|DEPRECATED: Inadvertently Introduced Weakness|category
CWE-519|DEPRECATED: .NET Environment Issues|category
CWE-520|.NET Misconfiguration: Use of Impersonation|weakness
CWE-521|Weak Password Requirements|weakness
CWE-522|Insufficiently Protected Credentials|weakness
CWE-523|Unprotected Transport of Credentials|weakness
CWE-524|Use of Cache Containing Sensitive Information|weakness
CWE-525|Use of Web Browser Cache Containing Sensitive Information|weakness
CWE-526|Cleartext Storage of Sensitive Information in an Environment Variable|weakness
CWE-527|Exposure of Version-Control Repository to an Unauthorized Control Sphere|weakness
CWE-528|Exposure of Core Dump File to an Unauthorized Control Sphere|weakness
CWE-529|Exposure of Access Control List Files to an Unauthorized Control Sphere|weakness
CWE-530|Exposure of Backup File to an Unauthorized Control Sphere|weakness
CWE-531|Inclusion of Sensitive Information in Test Code|weakness
CWE-532|Insertion of Sensitive Information into Log File|weakness
CWE-533|DEPRECATED: Information Exposure Through Server Log Files|weakness
CWE-534|DEPRECATED: Information Exposure Through Debug Log Files|weakness
CWE-535|Exposure of Information Through Shell Error Message|weakness
CWE-536|Servlet Runtime Error Message Containing Sensitive Information|weakness
CWE-537|Java Runtime Error Message Containing Sensitive Information|weakness
CWE-538|Insertion of Sensitive Information into Externally-Accessible File or Directory|weakness
CWE-539|Use of Persistent Cookies Containing Sensitive Information|weakness
CWE-540|Inclusion of Sensitive Information in Source Code|weakness
CWE-541|Inclusion of Sensitive Information in an Include File|weakness
CWE-542|DEPRECATED: Information Exposure Through Cleanup Log Files|weakness
CWE-543|Use of Singleton Pattern Without Synchronization in a Multithreaded Context|weakness
CWE-544|Missing Standardized Error Handling Mechanism|weakness
CWE-545|DEPRECATED: Use of Dynamic Class Loading|weakness
CWE-546|Suspicious Comment|weakness
CWE-547|Use of Hard-coded, Security-relevant Constants|weakness
CWE-548|Exposure of Information Through Directory Listing|weakness
CWE-549|Missing Password Field Masking|weakness
CWE-550|Server-generated Error Message Containing Sensitive Information|weakness
CWE-551|Incorrect Behavior Order: Authorization Before Parsing and Canonicalization|weakness
CWE-552|Files or Directories Accessible to External Parties|weakness
CWE-553|Command Shell in Externally Accessible Directory|weakness
CWE-554|ASP.NET Misconfiguration: Not Using Input Validation Framework|weakness
CWE-555|J2EE Misconfiguration: Plaintext Password in Configuration File|weakness
CWE-556|ASP.NET Misconfiguration: Use of Identity Impersonation|weakness
CWE-557|Concurrency Issues|category
CWE-558|Use of getlogin() in Multithreaded Application|weakness
CWE-559|DEPRECATED: Often Misused: Arguments and Parameters|category
CWE-560|Use of umask() with chmod-style Argument|weakness
CWE-561|Dead Code|weakness
CWE-562|Return of Stack Variable Address|weakness
CWE-563|Assignment to Variable without Use|weakness
CWE-564|SQL Injection: Hibernate|weakness
CWE-565|Reliance on Cookies without Validation and Integrity Checking|weakness
CWE-566|Authorization Bypass Through User-Controlled SQL Primary Key|weakness
CWE-567|Unsynchronized Access to Shared Data in a Multithreaded Context|weakness
CWE-568|finalize() Method Without super.finalize()|weakness
CWE-569|Expression Issues|category
CWE-570|Expression is Always False|weakness
CWE-571|Expression is Always True|weakness
CWE-572|Call to Thread run() instead of start()|weakness
CWE-573|Improper Following of Specification by Caller|weakness
CWE-574|EJB Bad Practices: Use of Synchronization Primitives|weakness
CWE-575|EJB Bad Practices: Use of AWT Swing|weakness
CWE-576|EJB Bad Practices: Use of Java I/O|weakness
CWE-577|EJB Bad Practices: Use of Sockets|weakness
CWE-578|EJB Bad Practices: Use of Class Loader|weakness
CWE-579|J2EE Bad Practices: Non-serializable Object Stored in Session|weakness
CWE-580|clone() Method Without super.clone()|weakness
CWE-581|Object Model Violation: Just One of Equals and Hashcode Defined|weakness
CWE-582|Array Declared Public, Final, and Static|weakness
CWE-583|finalize() Method Declared Public|weakness
CWE-584|Return Inside Finally Block|weakness
CWE-585|Empty Synchronized Block|weakness
CWE-586|Explicit Call to Finalize()|weakness
CWE-587|Assignment of a Fixed Address to a Pointer|weakness
CWE-588|Attempt to Access Child of a Non-structure Pointer|weakness
CWE-589|Call to Non-ubiquitous API|weakness
CWE-590|Free of Memory not on the Heap|weakness
CWE-591|Sensitive Data Storage in Improperly Locked Memory|weakness
CWE-592|DEPRECATED: Authentication Bypass Issues|weakness
CWE-593|Authentication Bypass: OpenSSL CTX Object Modified after SSL Objects are Created|weakness
CWE-594|J2EE Framework: Saving Unserializable Objects to Disk|weakness
CWE-595|Comparison of Object References Instead of Object Contents|weakness
CWE-596|DEPRECATED: Incorrect Semantic Object Comparison|weakness
CWE-597|Use of Wrong Operator in String Comparison|weakness
CWE-598|Use of GET Request Method With Sensitive Query Strings|weakness
CWE-599|Missing Validation of OpenSSL Certificate|weakness
CWE-600|Uncaught Exception in Servlet |weakness
CWE-601|URL Redirection to Untrusted Site ('Open Redirect')|weakness
CWE-602|Client-Side Enforcement of Server-Side Security|weakness
CWE-603|Use of Client-Side Authentication|weakness
CWE-604|Deprecated Entries|view
CWE-605|Multiple Binds to the Same Port|weakness
CWE-606|Unchecked Input for Loop Condition|weakness
CWE-607|Public Static Final Field References Mutable Object|weakness
CWE-608|Struts: Non-private Field in ActionForm Class|weakness
CWE-609|Double-Checked Locking|weakness
CWE-610|Externally Controlled Reference to a Resource in Another Sphere|weakness
CWE-611|Improper Restriction of XML External Entity Reference|weakness
CWE-612|Improper Authorization of Index Containing Sensitive Information|weakness
CWE-613|Insufficient Session Expiration|weakness
CWE-614|Sensitive Cookie in HTTPS Session Without 'Secure' Attribute|weakness
CWE-615|Inclusion of Sensitive Information in Source Code Comments|weakness
CWE-616|Incomplete Identification of Uploaded File Variables (PHP)|weakness
CWE-617|Reachable Assertion|weakness
CWE-618|Exposed Unsafe ActiveX Method|weakness
CWE-619|Dangling Database Cursor ('Cursor Injection')|weakness
CWE-620|Unverified Password Change|weakness
CWE-621|Variable Extraction Error|weakness
CWE-622|Improper Validation of Function Hook Arguments|weakness
CWE-623|Unsafe ActiveX Control Marked Safe For Scripting|weakness
CWE-624|Executable Regular Expression Error|weakness
CWE-625|Permissive Regular Expression|weakness
CWE-626|Null Byte Interaction Error (Poison Null Byte)|weakness
CWE-627|Dynamic Variable Evaluation|weakness
CWE-628|Function Call with Incorrectly Specified Arguments|weakness
CWE-629|Weaknesses in OWASP Top Ten (2007)|view
CWE-630|DEPRECATED: Weaknesses Examined by SAMATE|view
CWE-631|DEPRECATED: Resource-specific Weaknesses|view
CWE-632|DEPRECATED: Weaknesses that Affect Files or Directories|category
CWE-633|DEPRECATED: Weaknesses that Affect Memory|category
CWE-634|DEPRECATED: Weaknesses that Affect System Processes|category
CWE-635|Weaknesses Originally Used by NVD from 2008 to 2016|view
CWE-636|Not Failing Securely ('Failing Open')|weakness
CWE-637|Unnecessary Complexity in Protection Mechanism (Not Using 'Economy of Mechanism')|weakness
CWE-638|Not Using Complete Mediation|weakness
CWE-639|Authorization Bypass Through User-Controlled Key|weakness
CWE-640|Weak Password Recovery Mechanism for Forgotten Password|weakness
CWE-641|Improper Restriction of Names for Files and Other Resources|weakness
CWE-642|External Control of Critical State Data|weakness
CWE-643|Improper Neutralization of Data within XPath Expressions ('XPath Injection')|weakness
CWE-644|Improper Neutralization of HTTP Headers for Scripting Syntax|weakness
CWE-645|Overly Restrictive Account Lockout Mechanism|weakness
CWE-646|Reliance on File Name or Extension of Externally-Supplied File|weakness
CWE-647|Use of Non-Canonical URL Paths for Authorization Decisions|weakness
CWE-648|Incorrect Use of Privileged APIs|weakness
CWE-649|Reliance on Obfuscation or Encryption of Security-Relevant Inputs without Integrity Checking|weakness
CWE-650|Trusting HTTP Permission Methods on the Server Side|weakness
CWE-651|Exposure of WSDL File Containing Sensitive Information|weakness
CWE-652|Improper Neutralization of Data within XQuery Expressions ('XQuery Injection')|weakness
CWE-653|Improper Isolation or Compartmentalization|weakness
CWE-654|Reliance on a Single Factor in a Security Decision|weakness
CWE-655|Insufficient Psychological Acceptability|weakness
CWE-656|Reliance on Security Through Obscurity|weakness
CWE-657|Violation of Secure Design Principles|weakness
CWE-658|Weaknesses in Software Written in C|view
CWE-659|Weaknesses in Software Written in C++|view
CWE-660|Weaknesses in Software Written in Java|view
CWE-661|Weaknesses in Software Written in PHP|view
CWE-662|Improper Synchronization|weakness
CWE-663|Use of a Non-reentrant Function in a Concurrent Context|weakness
CWE-664|Improper Control of a Resource Through its Lifetime|weakness
CWE-665|Improper Initialization|weakness
CWE-666|Operation on Resource in Wrong Phase of Lifetime|weakness
CWE-667|Improper Locking|weakness
CWE-668|Exposure of Resource to Wrong Sphere|weakness
CWE-669|Incorrect Resource Transfer Between Spheres|weakness
CWE-670|Always-Incorrect Control Flow Implementation|weakness
CWE-671|Lack of Administrator Control over Security|weakness
CWE-672|Operation on a Resource after Expiration or Release|weakness
CWE-673|External Influence of Sphere Definition|weakness
CWE-674|Uncontrolled Recursion|weakness
CWE-675|Multiple Operations on Resource in Single-Operation Context|weakness
CWE-676|Use of Potentially Dangerous Function|weakness
CWE-677|Weakness Base Elements|view
CWE-678|Composites|view
CWE-679|DEPRECATED: Chain Elements|view
CWE-680|Integer Overflow to Buffer Overflow|weakness
CWE-681|Incorrect Conversion between Numeric Types|weakness
CWE-682|Incorrect Calculation|weakness
CWE-683|Function Call With Incorrect Order of Arguments|weakness
CWE-684|Incorrect Provision of Specified Functionality|weakness
CWE-685|Function Call With Incorrect Number of Arguments|weakness
CWE-686|Function Call With Incorrect Argument Type|weakness
CWE-687|Function Call With Incorrectly Specified Argument Value|weakness
CWE-688|Function Call With Incorrect Variable or Reference as Argument|weakness
CWE-689|Permission Race Condition During Resource Copy|weakness
CWE-690|Unchecked Return Value to NULL Pointer Dereference|weakness
CWE-691|Insufficient Control Flow Management|weakness
CWE-692|Incomplete Denylist to Cross-Site Scripting|weakness
CWE-693|Protection Mechanism Failure|weakness
CWE-694|Use of Multiple Resources with Duplicate Identifier|weakness
CWE-695|Use of Low-Level Functionality|weakness
CWE-696|Incorrect Behavior Order|weakness
CWE-697|Incorrect Comparison|weakness
CWE-698|Execution After Redirect (EAR)|weakness
CWE-699|Software Development|view
CWE-700|Seven Pernicious Kingdoms|view
CWE-701|Weaknesses Introduced During Design|view
CWE-702|Weaknesses Introduced During Implementation|view
CWE-703|Improper Check or Handling of Exceptional Conditions|weakness
CWE-704|Incorrect Type Conversion or Cast|weakness
CWE-705|Incorrect Control Flow Scoping|weakness
CWE-706|Use of Incorrectly-Resolved Name or Reference|weakness
CWE-707|Improper Neutralization|weakness
CWE-708|Incorrect Ownership Assignment|weakness
CWE-709|Named Chains|view
CWE-710|Improper Adherence to Coding Standards|weakness
CWE-711|Weaknesses in OWASP Top Ten (2004)|view
CWE-712|OWASP Top Ten 2007 Category A1 - Cross Site Scripting (XSS)|category
CWE-713|OWASP Top Ten 2007 Category A2 - Injection Flaws|category
CWE-714|OWASP Top Ten 2007 Category A3 - Malicious File Execution|category
CWE-715|OWASP Top Ten 2007 Category A4 - Insecure Direct Object Reference|category
CWE-716|OWASP Top Ten 2007 Category A5 - Cross Site Request Forgery (CSRF)|category
CWE-717|OWASP Top Ten 2007 Category A6 - Information Leakage and Improper Error Handling|category
CWE-718|OWASP Top Ten 2007 Category A7 - Broken Authentication and Session Management|category
CWE-719|OWASP Top Ten 2007 Category A8 - Insecure Cryptographic Storage|category
CWE-720|OWASP Top Ten 2007 Category A9 - Insecure Communications|category
CWE-721|OWASP Top Ten 2007 Category A10 - Failure to Restrict URL Access|category
CWE-722|OWASP Top Ten 2004 Category A1 - Unvalidated Input|category
CWE-723|OWASP Top Ten 2004 Category A2 - Broken Access Control|category
CWE-724|OWASP Top Ten 2004 Category A3 - Broken Authentication and Session Management|category
CWE-725|OWASP Top Ten 2004 Category A4 - Cross-Site Scripting (XSS) Flaws|category
CWE-726|OWASP Top Ten 2004 Category A5 - Buffer Overflows|category
CWE-727|OWASP Top Ten 2004 Category A6 - Injection Flaws|category
CWE-728|OWASP Top Ten 2004 Category A7 - Improper Error Handling|category
CWE-729|OWASP Top Ten 2004 Category A8 - Insecure Storage|category
CWE-730|OWASP Top Ten 2004 Category A9 - Denial of Service|category
CWE-731|OWASP Top Ten 2004 Category A10 - Insecure Configuration Management|category
CWE-732|Incorrect Permission Assignment for Critical Resource|weakness
CWE-733|Compiler Optimization Removal or Modification of Security-critical Code|weakness
CWE-734|Weaknesses Addressed by the CERT C Secure Coding Standard (2008)|view
CWE-735|CERT C Secure Coding Standard (2008) Chapter 2 - Preprocessor (PRE)|category
CWE-736|CERT C Secure Coding Standard (2008) Chapter 3 - Declarations and Initialization (DCL)|category
CWE-737|CERT C Secure Coding Standard (2008) Chapter 4 - Expressions (EXP)|category
CWE-738|CERT C Secure Coding Standard (2008) Chapter 5 - Integers (INT)|category
CWE-739|CERT C Secure Coding Standard (2008) Chapter 6 - Floating Point (FLP)|category
CWE-740|CERT C Secure Coding Standard (2008) Chapter 7 - Arrays (ARR)|category
CWE-741|CERT C Secure Coding Standard (2008) Chapter 8 - Characters and Strings (STR)|category
CWE-742|CERT C Secure Coding Standard (2008) Chapter 9 - Memory Management (MEM)|category
CWE-743|CERT C Secure Coding Standard (2008) Chapter 10 - Input Output (FIO)|category
CWE-744|CERT C Secure Coding Standard (2008) Chapter 11 - Environment (ENV)|category
CWE-745|CERT C Secure Coding Standard (2008) Chapter 12 - Signals (SIG)|category
CWE-746|CERT C Secure Coding Standard (2008) Chapter 13 - Error Handling (ERR)|category
CWE-747|CERT C Secure Coding Standard (2008) Chapter 14 - Miscellaneous (MSC)|category
CWE-748|CERT C Secure Coding Standard (2008) Appendix - POSIX (POS)|category
CWE-749|Exposed Dangerous Method or Function|weakness
CWE-750|Weaknesses in the 2009 CWE/SANS Top 25 Most Dangerous Programming Errors|view
CWE-751|2009 Top 25 - Insecure Interaction Between Components|category
CWE-752|2009 Top 25 - Risky Resource Management|category
CWE-753|2009 Top 25 - Porous Defenses|category
CWE-754|Improper Check for Unusual or Exceptional Conditions|weakness
CWE-755|Improper Handling of Exceptional Conditions|weakness
CWE-756|Missing Custom Error Page|weakness
CWE-757|Selection of Less-Secure Algorithm During Negotiation ('Algorithm Downgrade')|weakness
CWE-758|Reliance on Undefined, Unspecified, or Implementation-Defined Behavior|weakness
CWE-759|Use of a One-Way Hash without a Salt|weakness
CWE-760|Use of a One-Way Hash with a Predictable Salt|weakness
CWE-761|Free of Pointer not at Start of Buffer|weakness
CWE-762|Mismatched Memory Management Routines|weakness
CWE-763|Release of Invalid Pointer or Reference|weakness
CWE-764|Multiple Locks of a Critical Resource|weakness
CWE-765|Multiple Unlocks of a Critical Resource|weakness
CWE-766|Critical Data Element Declared Public|weakness
CWE-767|Access to Critical Private Variable via Public Method|weakness
CWE-768|Incorrect Short Circuit Evaluation|weakness
CWE-769|DEPRECATED: Uncontrolled File Descriptor Consumption|weakness
CWE-770|Allocation of Resources Without Limits or Throttling|weakness
CWE-771|Missing Reference to Active Allocated Resource|weakness
CWE-772|Missing Release of Resource after Effective Lifetime|weakness
CWE-773|Missing Reference to Active File Descriptor or Handle|weakness
CWE-774|Allocation of File Descriptors or Handles Without Limits or Throttling|weakness
CWE-775|Missing Release of File Descriptor or Handle after Effective Lifetime|weakness
CWE-776|Improper Restriction of Recursive Entity References in DTDs ('XML Entity Expansion')|weakness
CWE-777|Regular Expression without Anchors|weakness
CWE-778|Insufficient Logging|weakness
CWE-779|Logging of Excessive Data|weakness
CWE-780|Use of RSA Algorithm without OAEP|weakness
CWE-781|Improper Address Validation in IOCTL with METHOD_NEITHER I/O Control Code|weakness
CWE-782|Exposed IOCTL with Insufficient Access Control|weakness
CWE-783|Operator Precedence Logic Error|weakness
CWE-784|Reliance on Cookies without Validation and Integrity Checking in a Security Decision|weakness
CWE-785|Use of Path Manipulation Function without Maximum-sized Buffer|weakness
CWE-786|Access of Memory Location Before Start of Buffer|weakness
CWE-787|Out-of-bounds Write|weakness
CWE-788|Access of Memory Location After End of Buffer|weakness
CWE-789|Memory Allocation with Excessive Size Value|weakness
CWE-790|Improper Filtering of Special Elements|weakness
CWE-791|Incomplete Filtering of Special Elements|weakness
CWE-792|Incomplete Filtering of One or More Instances of Special Elements|weakness
CWE-793|Only Filtering One Instance of a Special Element|weakness
CWE-794|Incomplete Filtering of Multiple Instances of Special Elements|weakness
CWE-795|Only Filtering Special Elements at a Specified Location|weakness
CWE-796|Only Filtering Special Elements Relative to a Marker|weakness
CWE-797|Only Filtering Special Elements at an Absolute Position|weakness
CWE-798|Use of Hard-coded Credentials|weakness
CWE-799|Improper Control of Interaction Frequency|weakness
CWE-800|Weaknesses in the 2010 CWE/SANS Top 25 Most Dangerous Programming Errors|view
CWE-801|2010 Top 25 - Insecure Interaction Between Components|category
CWE-802|2010 Top 25 - Risky Resource Management|category
CWE-803|2010 Top 25 - Porous Defenses|category
CWE-804|Guessable CAPTCHA|weakness
CWE-805|Buffer Access with Incorrect Length Value|weakness
CWE-806|Buffer Access Using Size of Source Buffer|weakness
CWE-807|Reliance on Untrusted Inputs in a Security Decision|weakness
CWE-808|2010 Top 25 - Weaknesses On the Cusp|category
CWE-809|Weaknesses in OWASP Top Ten (2010)|view
CWE-810|OWASP Top Ten 2010 Category A1 - Injection|category
CWE-811|OWASP Top Ten 2010 Category A2 - Cross-Site Scripting (XSS)|category
CWE-812|OWASP Top Ten 2010 Category A3 - Broken Authentication and Session Management|category
CWE-813|OWASP Top Ten 2010 Category A4 - Insecure Direct Object References|category
CWE-814|OWASP Top Ten 2010 Category A5 - Cross-Site Request Forgery(CSRF)|category
CWE-815|OWASP Top Ten 2010 Category A6 - Security Misconfiguration|category
CWE-816|OWASP Top Ten 2010 Category A7 - Insecure Cryptographic Storage|category
CWE-817|OWASP Top Ten 2010 Category A8 - Failure to Restrict URL Access|category
CWE-818|OWASP Top Ten 2010 Category A9 - Insufficient Transport Layer Protection|category
CWE-819|OWASP Top Ten 2010 Category A10 - Unvalidated Redirects and Forwards|category
CWE-820|Missing Synchronization|weakness
CWE-821|Incorrect Synchronization|weakness
CWE-822|Untrusted Pointer Dereference|weakness
CWE-823|Use of Out-of-range Pointer Offset|weakness
CWE-824|Access of Uninitialized Pointer|weakness
CWE-825|Expired Pointer Dereference|weakness
CWE-826|Premature Release of Resource During Expected Lifetime|weakness
CWE-827|Improper Control of Document Type Definition|weakness
CWE-828|Signal Handler with Functionality that is not Asynchronous-Safe|weakness
CWE-829|Inclusion of Functionality from Untrusted Control Sphere|weakness
CWE-830|Inclusion of Web Functionality from an Untrusted Source|weakness
CWE-831|Signal Handler Function Associated with Multiple Signals|weakness
CWE-832|Unlock of a Resource that is not Locked|weakness
CWE-833|Deadlock|weakness
CWE-834|Excessive Iteration|weakness
CWE-835|Loop with Unreachable Exit Condition ('Infinite Loop')|weakness
CWE-836|Use of Password Hash Instead of Password for Authentication|weakness
CWE-837|Improper Enforcement of a Single, Unique Action|weakness
CWE-838|Inappropriate Encoding for Output Context|weakness
CWE-839|Numeric Range Comparison Without Minimum Check|weakness
CWE-840|Business Logic Errors|category
CWE-841|Improper Enforcement of Behavioral Workflow|weakness
CWE-842|Placement of User into Incorrect Group|weakness
CWE-843|Access of Resource Using Incompatible Type ('Type Confusion')|weakness
CWE-844|Weaknesses Addressed by The CERT Oracle Secure Coding Standard for Java (2011)|view
CWE-845|The CERT Oracle Secure Coding Standard for Java (2011) Chapter 2 - Input Validation and Data Sanitization (IDS)|category
CWE-846|The CERT Oracle Secure Coding Standard for Java (2011) Chapter 3 - Declarations and Initialization (DCL)|category
CWE-847|The CERT Oracle Secure Coding Standard for Java (2011) Chapter 4 - Expressions (EXP)|category
CWE-848|The CERT Oracle Secure Coding Standard for Java (2011) Chapter 5 - Numeric Types and Operations (NUM)|category
CWE-849|The CERT Oracle Secure Coding Standard for Java (2011) Chapter 6 - Object Orientation (OBJ)|category
CWE-850|The CERT Oracle Secure Coding Standard for Java (2011) Chapter 7 - Methods (MET)|category
CWE-851|The CERT Oracle Secure Coding Standard for Java (2011) Chapter 8 - Exceptional Behavior (ERR)|category
CWE-852|The CERT Oracle Secure Coding Standard for Java (2011) Chapter 9 - Visibility and Atomicity (VNA)|category
CWE-853|The CERT Oracle Secure Coding Standard for Java (2011) Chapter 10 - Locking (LCK)|category
CWE-854|The CERT Oracle Secure Coding Standard for Java (2011) Chapter 11 - Thread APIs (THI)|category
CWE-855|The CERT Oracle Secure Coding Standard for Java (2011) Chapter 12 - Thread Pools (TPS)|category
CWE-856|The CERT Oracle Secure Coding Standard for Java (2011) Chapter 13 - Thread-Safety Miscellaneous (TSM)|category
CWE-857|The CERT Oracle Secure Coding Standard for Java (2011) Chapter 14 - Input Output (FIO)|category
CWE-858|The CERT Oracle Secure Coding Standard for Java (2011) Chapter 15 - Serialization (SER)|category
CWE-859|The CERT Oracle Secure Coding Standard for Java (2011) Chapter 16 - Platform Security (SEC)|category
CWE-860|The CERT Oracle Secure Coding Standard for Java (2011) Chapter 17 - Runtime Environment (ENV)|category
CWE-861|The CERT Oracle Secure Coding Standard for Java (2011) Chapter 18 - Miscellaneous (MSC)|category
CWE-862|Missing Authorization|weakness
CWE-863|Incorrect Authorization|weakness
CWE-864|2011 Top 25 - Insecure Interaction Between Components|category
CWE-865|2011 Top 25 - Risky Resource Management|category
CWE-866|2011 Top 25 - Porous Defenses|category
CWE-867|2011 Top 25 - Weaknesses On the Cusp|category
CWE-868|Weaknesses Addressed by the SEI CERT C++ Coding Standard (2016 Version)|view
CWE-869|CERT C++ Secure Coding Section 01 - Preprocessor (PRE)|category
CWE-870|CERT C++ Secure Coding Section 02 - Declarations and Initialization (DCL)|category
CWE-871|CERT C++ Secure Coding Section 03 - Expressions (EXP)|category
CWE-872|CERT C++ Secure Coding Section 04 - Integers (INT)|category
CWE-873|CERT C++ Secure Coding Section 05 - Floating Point Arithmetic (FLP)|category
CWE-874|CERT C++ Secure Coding Section 06 - Arrays and the STL (ARR)|category
CWE-875|CERT C++ Secure Coding Section 07 - Characters and Strings (STR)|category
CWE-876|CERT C++ Secure Coding Section 08 - Memory Management (MEM)|category
CWE-877|CERT C++ Secure Coding Section 09 - Input Output (FIO)|category
CWE-878|CERT C++ Secure Coding Section 10 - Environment (ENV)|category
CWE-879|CERT C++ Secure Coding Section 11 - Signals (SIG)|category
CWE-880|CERT C++ Secure Coding Section 12 - Exceptions and Error Handling (ERR)|category
CWE-881|CERT C++ Secure Coding Section 13 - Object Oriented Programming (OOP)|category
CWE-882|CERT C++ Secure Coding Section 14 - Concurrency (CON)|category
CWE-883|CERT C++ Secure Coding Section 49 - Miscellaneous (MSC)|category
CWE-884|CWE Cross-section|view
CWE-885|SFP Primary Cluster: Risky Values|category
CWE-886|SFP Primary Cluster: Unused entities|category
CWE-887|SFP Primary Cluster: API|category
CWE-888|Software Fault Pattern (SFP) Clusters|view
CWE-889|SFP Primary Cluster: Exception Management|category
CWE-890|SFP Primary Cluster: Memory Access|category
CWE-891|SFP Primary Cluster: Memory Management|category
CWE-892|SFP Primary Cluster: Resource Management|category
CWE-893|SFP Primary Cluster: Path Resolution|category
CWE-894|SFP Primary Cluster: Synchronization|category
CWE-895|SFP Primary Cluster: Information Leak|category
CWE-896|SFP Primary Cluster: Tainted Input|category
CWE-897|SFP Primary Cluster: Entry Points|category
CWE-898|SFP Primary Cluster: Authentication|category
CWE-899|SFP Primary Cluster: Access Control|category
CWE-900|Weaknesses in the 2011 CWE/SANS Top 25 Most Dangerous Software Errors|view
CWE-901|SFP Primary Cluster: Privilege|category
CWE-902|SFP Primary Cluster: Channel|category
CWE-903|SFP Primary Cluster: Cryptography|category
CWE-904|SFP Primary Cluster: Malware|category
CWE-905|SFP Primary Cluster: Predictability|category
CWE-906|SFP Primary Cluster: UI|category
CWE-907|SFP Primary Cluster: Other|category
CWE-908|Use of Uninitialized Resource|weakness
CWE-909|Missing Initialization of Resource|weakness
CWE-910|Use of Expired File Descriptor|weakness
CWE-911|Improper Update of Reference Count|weakness
CWE-912|Hidden Functionality|weakness
CWE-913|Improper Control of Dynamically-Managed Code Resources|weakness
CWE-914|Improper Control of Dynamically-Identified Variables|weakness
CWE-915|Improperly Controlled Modification of Dynamically-Determined Object Attributes|weakness
CWE-916|Use of Password Hash With Insufficient Computational Effort|weakness
CWE-917|Improper Neutralization of Special Elements used in an Expression Language Statement ('Expression Language Injection')|weakness
CWE-918|Server-Side Request Forgery (SSRF)|weakness
CWE-919|Weaknesses in Mobile Applications|view
CWE-920|Improper Restriction of Power Consumption|weakness
CWE-921|Storage of Sensitive Data in a Mechanism without Access Control|weakness
CWE-922|Insecure Storage of Sensitive Information|weakness
CWE-923|Improper Restriction of Communication Channel to Intended Endpoints|weakness
CWE-924|Improper Enforcement of Message Integrity During Transmission in a Communication Channel|weakness
CWE-925|Improper Verification of Intent by Broadcast Receiver|weakness
CWE-926|Improper Export of Android Application Components|weakness
CWE-927|Use of Implicit Intent for Sensitive Communication|weakness
CWE-928|Weaknesses in OWASP Top Ten (2013)|view
CWE-929|OWASP Top Ten 2013 Category A1 - Injection|category
CWE-930|OWASP Top Ten 2013 Category A2 - Broken Authentication and Session Management|category
CWE-931|OWASP Top Ten 2013 Category A3 - Cross-Site Scripting (XSS)|category
CWE-932|OWASP Top Ten 2013 Category A4 - Insecure Direct Object References|category
CWE-933|OWASP Top Ten 2013 Category A5 - Security Misconfiguration|category
CWE-934|OWASP Top Ten 2013 Category A6 - Sensitive Data Exposure|category
CWE-935|OWASP Top Ten 2013 Category A7 - Missing Function Level Access Control|category
CWE-936|OWASP Top Ten 2013 Category A8 - Cross-Site Request Forgery (CSRF)|category
CWE-937|OWASP Top Ten 2013 Category A9 - Using Components with Known Vulnerabilities|category
CWE-938|OWASP Top Ten 2013 Category A10 - Unvalidated Redirects and Forwards|category
CWE-939|Improper Authorization in Handler for Custom URL Scheme|weakness
CWE-940|Improper Verification of Source of a Communication Channel|weakness
CWE-941|Incorrectly Specified Destination in a Communication Channel|weakness
CWE-942|Permissive Cross-domain Policy with Untrusted Domains|weakness
CWE-943|Improper Neutralization of Special Elements in Data Query Logic|weakness
CWE-944|SFP Secondary Cluster: Access Management|category
CWE-945|SFP Secondary Cluster: Insecure Resource Access|category
CWE-946|SFP Secondary Cluster: Insecure Resource Permissions|category
CWE-947|SFP Secondary Cluster: Authentication Bypass|category
CWE-948|SFP Secondary Cluster: Digital Certificate|category
CWE-949|SFP Secondary Cluster: Faulty Endpoint Authentication|category
CWE-950|SFP Secondary Cluster: Hardcoded Sensitive Data|category
CWE-951|SFP Secondary Cluster: Insecure Authentication Policy|category
CWE-952|SFP Secondary Cluster: Missing Authentication|category
CWE-953|SFP Secondary Cluster: Missing Endpoint Authentication|category
CWE-954|SFP Secondary Cluster: Multiple Binds to the Same Port|category
CWE-955|SFP Secondary Cluster: Unrestricted Authentication|category
CWE-956|SFP Secondary Cluster: Channel Attack|category
CWE-957|SFP Secondary Cluster: Protocol Error|category
CWE-958|SFP Secondary Cluster: Broken Cryptography|category
CWE-959|SFP Secondary Cluster: Weak Cryptography|category
CWE-960|SFP Secondary Cluster: Ambiguous Exception Type|category
CWE-961|SFP Secondary Cluster: Incorrect Exception Behavior|category
CWE-962|SFP Secondary Cluster: Unchecked Status Condition|category
CWE-963|SFP Secondary Cluster: Exposed Data|category
CWE-964|SFP Secondary Cluster: Exposure Temporary File|category
CWE-965|SFP Secondary Cluster: Insecure Session Management|category
CWE-966|SFP Secondary Cluster: Other Exposures|category
CWE-967|SFP Secondary Cluster: State Disclosure|category
CWE-968|SFP Secondary Cluster: Covert Channel|category
CWE-969|SFP Secondary Cluster: Faulty Memory Release|category
CWE-970|SFP Secondary Cluster: Faulty Buffer Access|category
CWE-971|SFP Secondary Cluster: Faulty Pointer Use|category
CWE-972|SFP Secondary Cluster: Faulty String Expansion|category
CWE-973|SFP Secondary Cluster: Improper NULL Termination|category
CWE-974|SFP Secondary Cluster: Incorrect Buffer Length Computation|category
CWE-975|SFP Secondary Cluster: Architecture|category
CWE-976|SFP Secondary Cluster: Compiler|category
CWE-977|SFP Secondary Cluster: Design|category
CWE-978|SFP Secondary Cluster: Implementation|category
CWE-979|SFP Secondary Cluster: Failed Chroot Jail|category
CWE-980|SFP Secondary Cluster: Link in Resource Name Resolution|category
CWE-981|SFP Secondary Cluster: Path Traversal|category
CWE-982|SFP Secondary Cluster: Failure to Release Resource|category
CWE-983|SFP Secondary Cluster: Faulty Resource Use|category
CWE-984|SFP Secondary Cluster: Life Cycle|category
CWE-985|SFP Secondary Cluster: Unrestricted Consumption|category
CWE-986|SFP Secondary Cluster: Missing Lock|category
CWE-987|SFP Secondary Cluster: Multiple Locks/Unlocks|category
CWE-988|SFP Secondary Cluster: Race Condition Window|category
CWE-989|SFP Secondary Cluster: Unrestricted Lock|category
CWE-990|SFP Secondary Cluster: Tainted Input to Command|category
CWE-991|SFP Secondary Cluster: Tainted Input to Environment|category
CWE-992|SFP Secondary Cluster: Faulty Input Transformation|category
CWE-993|SFP Secondary Cluster: Incorrect Input Handling|category
CWE-994|SFP Secondary Cluster: Tainted Input to Variable|category
CWE-995|SFP Secondary Cluster: Feature|category
CWE-996|SFP Secondary Cluster: Security|category
CWE-997|SFP Secondary Cluster: Information Loss|category
CWE-998|SFP Secondary Cluster: Glitch in Computation|category
CWE-999|DEPRECATED: Weaknesses without Software Fault Patterns|view
CWE-1000|Research Concepts|view
CWE-1001|SFP Secondary Cluster: Use of an Improper API|category
CWE-1002|SFP Secondary Cluster: Unexpected Entry Points|category
CWE-1003|Weaknesses for Simplified Mapping of Published Vulnerabilities|view
CWE-1004|Sensitive Cookie Without 'HttpOnly' Flag|weakness
CWE-1005|7PK - Input Validation and Representation|category
CWE-1006|Bad Coding Practices|category
CWE-1007|Insufficient Visual Distinction of Homoglyphs Presented to User|weakness
CWE-1008|Architectural Concepts|view
CWE-1009|Audit|category
CWE-1010|Authenticate Actors|category
CWE-1011|Authorize Actors|category
CWE-1012|Cross Cutting|category
CWE-1013|Encrypt Data|category
CWE-1014|Identify Actors|category
CWE-1015|Limit Access|category
CWE-1016|Limit Exposure|category
CWE-1017|Lock Computer|category
CWE-1018|Manage User Sessions|category
CWE-1019|Validate Inputs|category
CWE-1020|Verify Message Integrity|category
CWE-1021|Improper Restriction of Rendered UI Layers or Frames|weakness
CWE-1022|Use of Web Link to Untrusted Target with window.opener Access|weakness
CWE-1023|Incomplete Comparison with Missing Factors|weakness
CWE-1024|Comparison of Incompatible Types|weakness
CWE-1025|Comparison Using Wrong Factors|weakness
CWE-1026|Weaknesses in OWASP Top Ten (2017)|view
CWE-1027|OWASP Top Ten 2017 Category A1 - Injection|category
CWE-1028|OWASP Top Ten 2017 Category A2 - Broken Authentication|category
CWE-1029|OWASP Top Ten 2017 Category A3 - Sensitive Data Exposure|category
CWE-1030|OWASP Top Ten 2017 Category A4 - XML External Entities (XXE)|category
CWE-1031|OWASP Top Ten 2017 Category A5 - Broken Access Control|category
CWE-1032|OWASP Top Ten 2017 Category A6 - Security Misconfiguration|category
CWE-1033|OWASP Top Ten 2017 Category A7 - Cross-Site Scripting (XSS)|category
CWE-1034|OWASP Top Ten 2017 Category A8 - Insecure Deserialization|category
CWE-1035|OWASP Top Ten 2017 Category A9 - Using Components with Known Vulnerabilities|category
CWE-1036|OWASP Top Ten 2017 Category A10 - Insufficient Logging & Monitoring|category
CWE-1037|Processor Optimization Removal or Modification of Security-critical Code|weakness
CWE-1038|Insecure Automated Optimizations|weakness
CWE-1039|Automated Recognition Mechanism with Inadequate Detection or Handling of Adversarial Input Perturbations|weakness
CWE-1040|Quality Weaknesses with Indirect Security Impacts|view
CWE-1041|Use of Redundant Code|weakness
CWE-1042|Static Member Data Element outside of a Singleton Class Element|weakness
CWE-1043|Data Element Aggregating an Excessively Large Number of Non-Primitive Elements|weakness
CWE-1044|Architecture with Number of Horizontal Layers Outside of Expected Range|weakness
CWE-1045|Parent Class with a Virtual Destructor and a Child Class without a Virtual Destructor|weakness
CWE-1046|Creation of Immutable Text Using String Concatenation|weakness
CWE-1047|Modules with Circular Dependencies|weakness
CWE-1048|Invokable Control Element with Large Number of Outward Calls|weakness
CWE-1049|Excessive Data Query Operations in a Large Data Table|weakness
CWE-1050|Excessive Platform Resource Consumption within a Loop|weakness
CWE-1051|Initialization with Hard-Coded Network Resource Configuration Data|weakness
CWE-1052|Excessive Use of Hard-Coded Literals in Initialization|weakness
CWE-1053|Missing Documentation for Design|weakness
CWE-1054|Invocation of a Control Element at an Unnecessarily Deep Horizontal Layer|weakness
CWE-1055|Multiple Inheritance from Concrete Classes|weakness
CWE-1056|Invokable Control Element with Variadic Parameters|weakness
CWE-1057|Data Access Operations Outside of Expected Data Manager Component|weakness
CWE-1058|Invokable Control Element in Multi-Thread Context with non-Final Static Storable or Member Element|weakness
CWE-1059|Insufficient Technical Documentation|weakness
CWE-1060|Excessive Number of Inefficient Server-Side Data Accesses|weakness
CWE-1061|Insufficient Encapsulation|weakness
CWE-1062|Parent Class with References to Child Class|weakness
CWE-1063|Creation of Class Instance within a Static Code Block|weakness
CWE-1064|Invokable Control Element with Signature Containing an Excessive Number of Parameters|weakness
CWE-1065|Runtime Resource Management Control Element in a Component Built to Run on Application Servers|weakness
CWE-1066|Missing Serialization Control Element|weakness
CWE-1067|Excessive Execution of Sequential Searches of Data Resource|weakness
CWE-1068|Inconsistency Between Implementation and Documented Design|weakness
CWE-1069|Empty Exception Block|weakness
CWE-1070|Serializable Data Element Containing non-Serializable Item Elements|weakness
CWE-1071|Empty Code Block|weakness
CWE-1072|Data Resource Access without Use of Connection Pooling|weakness
CWE-1073|Non-SQL Invokable Control Element with Excessive Number of Data Resource Accesses|weakness
CWE-1074|Class with Excessively Deep Inheritance|weakness
CWE-1075|Unconditional Control Flow Transfer outside of Switch Block|weakness
CWE-1076|Insufficient Adherence to Expected Conventions|weakness
CWE-1077|Floating Point Comparison with Incorrect Operator|weakness
CWE-1078|Inappropriate Source Code Style or Formatting|weakness
CWE-1079|Parent Class without Virtual Destructor Method|weakness
CWE-1080|Source Code File with Excessive Number of Lines of Code|weakness
CWE-1081|Entries with Maintenance Notes|view
CWE-1082|Class Instance Self Destruction Control Element|weakness
CWE-1083|Data Access from Outside Expected Data Manager Component|weakness
CWE-1084|Invokable Control Element with Excessive File or Data Access Operations|weakness
CWE-1085|Invokable Control Element with Excessive Volume of Commented-out Code|weakness
CWE-1086|Class with Excessive Number of Child Classes|weakness
CWE-1087|Class with Virtual Method without a Virtual Destructor|weakness
CWE-1088|Synchronous Access of Remote Resource without Timeout|weakness
CWE-1089|Large Data Table with Excessive Number of Indices|weakness
CWE-1090|Method Containing Access of a Member Element from Another Class|weakness
CWE-1091|Use of Object without Invoking Destructor Method|weakness
CWE-1092|Use of Same Invokable Control Element in Multiple Architectural Layers|weakness
CWE-1093|Excessively Complex Data Representation|weakness
CWE-1094|Excessive Index Range Scan for a Data Resource|weakness
CWE-1095|Loop Condition Value Update within the Loop|weakness
CWE-1096|Singleton Class Instance Creation without Proper Locking or Synchronization|weakness
CWE-1097|Persistent Storable Data Element without Associated Comparison Control Element|weakness
CWE-1098|Data Element containing Pointer Item without Proper Copy Control Element|weakness
CWE-1099|Inconsistent Naming Conventions for Identifiers|weakness
CWE-1100|Insufficient Isolation of System-Dependent Functions|weakness
CWE-1101|Reliance on Runtime Component in Generated Code|weakness
CWE-1102|Reliance on Machine-Dependent Data Representation|weakness
CWE-1103|Use of Platform-Dependent Third Party Components|weakness
CWE-1104|Use of Unmaintained Third Party Components|weakness
CWE-1105|Insufficient Encapsulation of Machine-Dependent Functionality|weakness
CWE-1106|Insufficient Use of Symbolic Constants|weakness
CWE-1107|Insufficient Isolation of Symbolic Constant Definitions|weakness
CWE-1108|Excessive Reliance on Global Variables|weakness
CWE-1109|Use of Same Variable for Multiple Purposes|weakness
CWE-1110|Incomplete Design Documentation|weakness
CWE-1111|Incomplete I/O Documentation|weakness
CWE-1112|Incomplete Documentation of Program Execution|weakness
CWE-1113|Inappropriate Comment Style|weakness
CWE-1114|Inappropriate Whitespace Style|weakness
CWE-1115|Source Code Element without Standard Prologue|weakness
CWE-1116|Inaccurate Comments|weakness
CWE-1117|Callable with Insufficient Behavioral Summary|weakness
CWE-1118|Insufficient Documentation of Error Handling Techniques|weakness
CWE-1119|Excessive Use of Unconditional Branching|weakness
CWE-1120|Excessive Code Complexity|weakness
CWE-1121|Excessive McCabe Cyclomatic Complexity|weakness
CWE-1122|Excessive Halstead Complexity|weakness
CWE-1123|Excessive Use of Self-Modifying Code|weakness
CWE-1124|Excessively Deep Nesting|weakness
CWE-1125|Excessive Attack Surface|weakness
CWE-1126|Declaration of Variable with Unnecessarily Wide Scope|weakness
CWE-1127|Compilation with Insufficient Warnings or Errors|weakness
CWE-1128|CISQ Quality Measures (2016)|view
CWE-1129|CISQ Quality Measures (2016) - Reliability|category
CWE-1130|CISQ Quality Measures (2016) - Maintainability|category
CWE-1131|CISQ Quality Measures (2016) - Security|category
CWE-1132|CISQ Quality Measures (2016) - Performance Efficiency|category
CWE-1133|Weaknesses Addressed by the SEI CERT Oracle Coding Standard for Java|view
CWE-1134|SEI CERT Oracle Secure Coding Standard for Java - Guidelines 00. Input Validation and Data Sanitization (IDS)|category
CWE-1135|SEI CERT Oracle Secure Coding Standard for Java - Guidelines 01. Declarations and Initialization (DCL)|category
CWE-1136|SEI CERT Oracle Secure Coding Standard for Java - Guidelines 02. Expressions (EXP)|category
CWE-1137|SEI CERT Oracle Secure Coding Standard for Java - Guidelines 03. Numeric Types and Operations (NUM)|category
CWE-1138|SEI CERT Oracle Secure Coding Standard for Java - Guidelines 04. Characters and Strings (STR)|category
CWE-1139|SEI CERT Oracle Secure Coding Standard for Java - Guidelines 05. Object Orientation (OBJ)|category
CWE-1140|SEI CERT Oracle Secure Coding Standard for Java - Guidelines 06. Methods (MET)|category
CWE-1141|SEI CERT Oracle Secure Coding Standard for Java - Guidelines 07. Exceptional Behavior (ERR)|category
CWE-1142|SEI CERT Oracle Secure Coding Standard for Java - Guidelines 08. Visibility and Atomicity (VNA)|category
CWE-1143|SEI CERT Oracle Secure Coding Standard for Java - Guidelines 09. Locking (LCK)|category
CWE-1144|SEI CERT Oracle Secure Coding Standard for Java - Guidelines 10. Thread APIs (THI)|category
CWE-1145|SEI CERT Oracle Secure Coding Standard for Java - Guidelines 11. Thread Pools (TPS)|category
CWE-1146|SEI CERT Oracle Secure Coding Standard for Java - Guidelines 12. Thread-Safety Miscellaneous (TSM)|category
CWE-1147|SEI CERT Oracle Secure Coding Standard for Java - Guidelines 13. Input Output (FIO)|category
CWE-1148|SEI CERT Oracle Secure Coding Standard for Java - Guidelines 14. Serialization (SER)|category
CWE-1149|SEI CERT Oracle Secure Coding Standard for Java - Guidelines 15. Platform Security (SEC)|category
CWE-1150|SEI CERT Oracle Secure Coding Standard for Java - Guidelines 16. Runtime Environment (ENV)|category
CWE-1151|SEI CERT Oracle Secure Coding Standard for Java - Guidelines 17. Java Native Interface (JNI)|category
CWE-1152|SEI CERT Oracle Secure Coding Standard for Java - Guidelines 49. Miscellaneous (MSC)|category
CWE-1153|SEI CERT Oracle Secure Coding Standard for Java - Guidelines 50. Android (DRD)|category
CWE-1154|Weaknesses Addressed by the SEI CERT C Coding Standard|view
CWE-1155|SEI CERT C Coding Standard - Guidelines 01. Preprocessor (PRE)|category
CWE-1156|SEI CERT C Coding Standard - Guidelines 02. Declarations and Initialization (DCL)|category
CWE-1157|SEI CERT C Coding Standard - Guidelines 03. Expressions (EXP)|category
CWE-1158|SEI CERT C Coding Standard - Guidelines 04. Integers (INT)|category
CWE-1159|SEI CERT C Coding Standard - Guidelines 05. Floating Point (FLP)|category
CWE-1160|SEI CERT C Coding Standard - Guidelines 06. Arrays (ARR)|category
CWE-1161|SEI CERT C Coding Standard - Guidelines 07. Characters and Strings (STR)|category
CWE-1162|SEI CERT C Coding Standard - Guidelines 08. Memory Management (MEM)|category
CWE-1163|SEI CERT C Coding Standard - Guidelines 09. Input Output (FIO)|category
CWE-1164|Irrelevant Code|weakness
CWE-1165|SEI CERT C Coding Standard - Guidelines 10. Environment (ENV)|category
CWE-1166|SEI CERT C Coding Standard - Guidelines 11. Signals (SIG)|category
CWE-1167|SEI CERT C Coding Standard - Guidelines 12. Error Handling (ERR)|category
CWE-1168|SEI CERT C Coding Standard - Guidelines 13. Application Programming Interfaces (API)|category
CWE-1169|SEI CERT C Coding Standard - Guidelines 14. Concurrency (CON)|category
CWE-1170|SEI CERT C Coding Standard - Guidelines 48. Miscellaneous (MSC)|category
CWE-1171|SEI CERT C Coding Standard - Guidelines 50. POSIX (POS)|category
CWE-1172|SEI CERT C Coding Standard - Guidelines 51. Microsoft Windows (WIN) |category
CWE-1173|Improper Use of Validation Framework|weakness
CWE-1174|ASP.NET Misconfiguration: Improper Model Validation|weakness
CWE-1175|SEI CERT Oracle Secure Coding Standard for Java - Guidelines 18. Concurrency (CON)|category
CWE-1176|Inefficient CPU Computation|weakness
CWE-1177|Use of Prohibited Code|weakness
CWE-1178|Weaknesses Addressed by the SEI CERT Perl Coding Standard|view
CWE-1179|SEI CERT Perl Coding Standard - Guidelines 01. Input Validation and Data Sanitization (IDS)|category
CWE-1180|SEI CERT Perl Coding Standard - Guidelines 02. Declarations and Initialization (DCL)|category
CWE-1181|SEI CERT Perl Coding Standard - Guidelines 03. Expressions (EXP)|category
CWE-1182|SEI CERT Perl Coding Standard - Guidelines 04. Integers (INT)|category
CWE-1183|SEI CERT Perl Coding Standard - Guidelines 05. Strings (STR)|category
CWE-1184|SEI CERT Perl Coding Standard - Guidelines 06. Object-Oriented Programming (OOP)|category
CWE-1185|SEI CERT Perl Coding Standard - Guidelines 07. File Input and Output (FIO)|category
CWE-1186|SEI CERT Perl Coding Standard - Guidelines 50. Miscellaneous (MSC)|category
CWE-1187|DEPRECATED: Use of Uninitialized Resource|weakness
CWE-1188|Insecure Default Initialization of Resource|weakness
CWE-1189|Improper Isolation of Shared Resources on System-on-a-Chip (SoC)|weakness
CWE-1190|DMA Device Enabled Too Early in Boot Phase|weakness
CWE-1191|On-Chip Debug and Test Interface With Improper Access Control|weakness
CWE-1192|System-on-Chip (SoC) Using Components without Unique, Immutable Identifiers|weakness
CWE-1193|Power-On of Untrusted Execution Core Before Enabling Fabric Access Control|weakness
CWE-1194|Hardware Design|view
CWE-1195|Manufacturing and Life Cycle Management Concerns|category
CWE-1196|Security Flow Issues|category
CWE-1197|Integration Issues|category
CWE-1198|Privilege Separation and Access Control Issues|category
CWE-1199|General Circuit and Logic Design Concerns|category
CWE-1200|Weaknesses in the 2019 CWE Top 25 Most Dangerous Software Errors|view
CWE-1201|Core and Compute Issues|category
CWE-1202|Memory and Storage Issues|category
CWE-1203|Peripherals, On-chip Fabric, and Interface/IO Problems|category
CWE-1204|Generation of Weak Initialization Vector (IV)|weakness
CWE-1205|Security Primitives and Cryptography Issues|category
CWE-1206|Power, Clock, Thermal, and Reset Concerns|category
CWE-1207|Debug and Test Problems|category
CWE-1208|Cross-Cutting Problems|category
CWE-1209|Failure to Disable Reserved Bits|weakness
CWE-1210|Audit / Logging Errors|category
CWE-1211|Authentication Errors|category
CWE-1212|Authorization Errors|category
CWE-1213|Random Number Issues|category
CWE-1214|Data Integrity Issues|category
CWE-1215|Data Validation Issues|category
CWE-1216|Lockout Mechanism Errors|category
CWE-1217|User Session Errors|category
CWE-1218|Memory Buffer Errors|category
CWE-1219|File Handling Issues|category
CWE-1220|Insufficient Granularity of Access Control|weakness
CWE-1221|Incorrect Register Defaults or Module Parameters|weakness
CWE-1222|Insufficient Granularity of Address Regions Protected by Register Locks|weakness
CWE-1223|Race Condition for Write-Once Attributes|weakness
CWE-1224|Improper Restriction of Write-Once Bit Fields|weakness
CWE-1225|Documentation Issues|category
CWE-1226|Complexity Issues|category
CWE-1227|Encapsulation Issues|category
CWE-1228|API / Function Errors|category
CWE-1229|Creation of Emergent Resource|weakness
CWE-1230|Exposure of Sensitive Information Through Metadata|weakness
CWE-1231|Improper Prevention of Lock Bit Modification|weakness
CWE-1232|Improper Lock Behavior After Power State Transition|weakness
CWE-1233|Security-Sensitive Hardware Controls with Missing Lock Bit Protection|weakness
CWE-1234|Hardware Internal or Debug Modes Allow Override of Locks|weakness
CWE-1235|Incorrect Use of Autoboxing and Unboxing for Performance Critical Operations|weakness
CWE-1236|Improper Neutralization of Formula Elements in a CSV File|weakness
CWE-1237|SFP Primary Cluster: Faulty Resource Release|category
CWE-1238|SFP Primary Cluster: Failure to Release Memory|category
CWE-1239|Improper Zeroization of Hardware Register|weakness
CWE-1240|Use of a Cryptographic Primitive with a Risky Implementation|weakness
CWE-1241|Use of Predictable Algorithm in Random Number Generator|weakness
CWE-1242|Inclusion of Undocumented Features or Chicken Bits|weakness
CWE-1243|Sensitive Non-Volatile Information Not Protected During Debug|weakness
CWE-1244|Internal Asset Exposed to Unsafe Debug Access Level or State|weakness
CWE-1245|Improper Finite State Machines (FSMs) in Hardware Logic|weakness
CWE-1246|Improper Write Handling in Limited-write Non-Volatile Memories|weakness
CWE-1247|Improper Protection Against Voltage and Clock Glitches|weakness
CWE-1248|Semiconductor Defects in Hardware Logic with Security-Sensitive Implications|weakness
CWE-1249|Application-Level Admin Tool with Inconsistent View of Underlying Operating System|weakness
CWE-1250|Improper Preservation of Consistency Between Independent Representations of Shared State|weakness
CWE-1251|Mirrored Regions with Different Values|weakness
CWE-1252|CPU Hardware Not Configured to Support Exclusivity of Write and Execute Operations|weakness
CWE-1253|Incorrect Selection of Fuse Values|weakness
CWE-1254|Incorrect Comparison Logic Granularity|weakness
CWE-1255|Comparison Logic is Vulnerable to Power Side-Channel Attacks|weakness
CWE-1256|Improper Restriction of Software Interfaces to Hardware Features|weakness
CWE-1257|Improper Access Control Applied to Mirrored or Aliased Memory Regions|weakness
CWE-1258|Exposure of Sensitive System Information Due to Uncleared Debug Information|weakness
CWE-1259|Improper Restriction of Security Token Assignment|weakness
CWE-1260|Improper Handling of Overlap Between Protected Memory Ranges|weakness
CWE-1261|Improper Handling of Single Event Upsets|weakness
CWE-1262|Improper Access Control for Register Interface|weakness
CWE-1263|Improper Physical Access Control|weakness
CWE-1264|Hardware Logic with Insecure De-Synchronization between Control and Data Channels|weakness
CWE-1265|Unintended Reentrant Invocation of Non-reentrant Code Via Nested Calls|weakness
CWE-1266|Improper Scrubbing of Sensitive Data from Decommissioned Device|weakness
CWE-1267|Policy Uses Obsolete Encoding|weakness
CWE-1268|Policy Privileges are not Assigned Consistently Between Control and Data Agents|weakness
CWE-1269|Product Released in Non-Release Configuration|weakness
CWE-1270|Generation of Incorrect Security Tokens|weakness
CWE-1271|Uninitialized Value on Reset for Registers Holding Security Settings|weakness
CWE-1272|Sensitive Information Uncleared Before Debug/Power State Transition|weakness
CWE-1273|Device Unlock Credential Sharing|weakness
CWE-1274|Improper Access Control for Volatile Memory Containing Boot Code|weakness
CWE-1275|Sensitive Cookie with Improper SameSite Attribute|weakness
CWE-1276|Hardware Child Block Incorrectly Connected to Parent System|weakness
CWE-1277|Firmware Not Updateable|weakness
CWE-1278|Missing Protection Against Hardware Reverse Engineering Using Integrated Circuit (IC) Imaging Techniques|weakness
CWE-1279|Cryptographic Operations are run Before Supporting Units are Ready|weakness
CWE-1280|Access Control Check Implemented After Asset is Accessed|weakness
CWE-1281|Sequence of Processor Instructions Leads to Unexpected Behavior|weakness
CWE-1282|Assumed-Immutable Data is Stored in Writable Memory|weakness
CWE-1283|Mutable Attestation or Measurement Reporting Data|weakness
CWE-1284|Improper Validation of Specified Quantity in Input|weakness
CWE-1285|Improper Validation of Specified Index, Position, or Offset in Input|weakness
CWE-1286|Improper Validation of Syntactic Correctness of Input|weakness
CWE-1287|Improper Validation of Specified Type of Input|weakness
CWE-1288|Improper Validation of Consistency within Input|weakness
CWE-1289|Improper Validation of Unsafe Equivalence in Input|weakness
CWE-1290|Incorrect Decoding of Security Identifiers |weakness
CWE-1291|Public Key Re-Use for Signing both Debug and Production Code|weakness
CWE-1292|Incorrect Conversion of Security Identifiers|weakness
CWE-1293|Missing Source Correlation of Multiple Independent Data|weakness
CWE-1294|Insecure Security Identifier Mechanism|weakness
CWE-1295|Debug Messages Revealing Unnecessary Information|weakness
CWE-1296|Incorrect Chaining or Granularity of Debug Components|weakness
CWE-1297|Unprotected Confidential Information on Device is Accessible by OSAT Vendors|weakness
CWE-1298|Hardware Logic Contains Race Conditions|weakness
CWE-1299|Missing Protection Mechanism for Alternate Hardware Interface|weakness
CWE-1300|Improper Protection of Physical Side Channels|weakness
CWE-1301|Insufficient or Incomplete Data Removal within Hardware Component|weakness
CWE-1302|Missing Security Identifier|weakness
CWE-1303|Non-Transparent Sharing of Microarchitectural Resources|weakness
CWE-1304|Improperly Preserved Integrity of Hardware Configuration State During a Power Save/Restore Operation|weakness
CWE-1305|CISQ Quality Measures (2020)|view
CWE-1306|CISQ Quality Measures - Reliability|category
CWE-1307|CISQ Quality Measures - Maintainability|category
CWE-1308|CISQ Quality Measures - Security|category
CWE-1309|CISQ Quality Measures - Efficiency|category
CWE-1310|Missing Ability to Patch ROM Code|weakness
CWE-1311|Improper Translation of Security Attributes by Fabric Bridge|weakness
CWE-1312|Missing Protection for Mirrored Regions in On-Chip Fabric Firewall|weakness
CWE-1313|Hardware Allows Activation of Test or Debug Logic at Runtime|weakness
CWE-1314|Missing Write Protection for Parametric Data Values|weakness
CWE-1315|Improper Setting of Bus Controlling Capability in Fabric End-point|weakness
CWE-1316|Fabric-Address Map Allows Programming of Unwarranted Overlaps of Protected and Unprotected Ranges|weakness
CWE-1317|Improper Access Control in Fabric Bridge|weakness
CWE-1318|Missing Support for Security Features in On-chip Fabrics or Buses|weakness
CWE-1319|Improper Protection against Electromagnetic Fault Injection (EM-FI)|weakness
CWE-1320|Improper Protection for Outbound Error Messages and Alert Signals|weakness
CWE-1321|Improperly Controlled Modification of Object Prototype Attributes ('Prototype Pollution')|weakness
CWE-1322|Use of Blocking Code in Single-threaded, Non-blocking Context|weakness
CWE-1323|Improper Management of Sensitive Trace Data|weakness
CWE-1324|DEPRECATED: Sensitive Information Accessible by Physical Probing of JTAG Interface|weakness
CWE-1325|Improperly Controlled Sequential Memory Allocation|weakness
CWE-1326|Missing Immutable Root of Trust in Hardware|weakness
CWE-1327|Binding to an Unrestricted IP Address|weakness
CWE-1328|Security Version Number Mutable to Older Versions|weakness
CWE-1329|Reliance on Component That is Not Updateable|weakness
CWE-1330|Remanent Data Readable after Memory Erase|weakness
CWE-1331|Improper Isolation of Shared Resources in Network On Chip (NoC)|weakness
CWE-1332|Improper Handling of Faults that Lead to Instruction Skips|weakness
CWE-1333|Inefficient Regular Expression Complexity|weakness
CWE-1334|Unauthorized Error Injection Can Degrade Hardware Redundancy|weakness
CWE-1335|Incorrect Bitwise Shift of Integer|weakness
CWE-1336|Improper Neutralization of Special Elements Used in a Template Engine|weakness
CWE-1337|Weaknesses in the 2021 CWE Top 25 Most Dangerous Software Weaknesses|view
CWE-1338|Improper Protections Against Hardware Overheating|weakness
CWE-1339|Insufficient Precision or Accuracy of a Real Number|weakness
CWE-1340|CISQ Data Protection Measures|view
CWE-1341|Multiple Releases of Same Resource or Handle|weakness
CWE-1342|Information Exposure through Microarchitectural State after Transient Execution|weakness
CWE-1343|Weaknesses in the 2021 CWE Most Important Hardware Weaknesses List|view
CWE-1344|Weaknesses in OWASP Top Ten (2021)|view
CWE-1345|OWASP Top Ten 2021 Category A01:2021 - Broken Access Control|category
CWE-1346|OWASP Top Ten 2021 Category A02:2021 - Cryptographic Failures|category
CWE-1347|OWASP Top Ten 2021 Category A03:2021 - Injection|category
CWE-1348|OWASP Top Ten 2021 Category A04:2021 - Insecure Design|category
CWE-1349|OWASP Top Ten 2021 Category A05:2021 - Security Misconfiguration|category
CWE-1350|Weaknesses in the 2020 CWE Top 25 Most Dangerous Software Weaknesses|view
CWE-1351|Improper Handling of Hardware Behavior in Exceptionally Cold Environments|weakness
CWE-1352|OWASP Top Ten 2021 Category A06:2021 - Vulnerable and Outdated Components|category
CWE-1353|OWASP Top Ten 2021 Category A07:2021 - Identification and Authentication Failures|category
CWE-1354|OWASP Top Ten 2021 Category A08:2021 - Software and Data Integrity Failures|category
CWE-1355|OWASP Top Ten 2021 Category A09:2021 - Security Logging and Monitoring Failures|category
CWE-1356|OWASP Top Ten 2021 Category A10:2021 - Server-Side Request Forgery (SSRF)|category
CWE-1357|Reliance on Insufficiently Trustworthy Component|weakness
CWE-1358|Weaknesses in SEI ETF Categories of Security Vulnerabilities in ICS|view
CWE-1359|ICS Communications|category
CWE-1360|ICS Dependencies (& Architecture)|category
CWE-1361|ICS Supply Chain|category
CWE-1362|ICS Engineering (Constructions/Deployment)|category
CWE-1363|ICS Operations (& Maintenance)|category
CWE-1364|ICS Communications: Zone Boundary Failures|category
CWE-1365|ICS Communications: Unreliability|category
CWE-1366|ICS Communications: Frail Security in Protocols|category
CWE-1367|ICS Dependencies (& Architecture): External Physical Systems|category
CWE-1368|ICS Dependencies (& Architecture): External Digital Systems|category
CWE-1369|ICS Supply Chain: IT/OT Convergence/Expansion|category
CWE-1370|ICS Supply Chain: Common Mode Frailties|category
CWE-1371|ICS Supply Chain: Poorly Documented or Undocumented Features|category
CWE-1372|ICS Supply Chain: OT Counterfeit and Malicious Corruption|category
CWE-1373|ICS Engineering (Construction/Deployment): Trust Model Problems|category
CWE-1374|ICS Engineering (Construction/Deployment): Maker Breaker Blindness|category
CWE-1375|ICS Engineering (Construction/Deployment): Gaps in Details/Data|category
CWE-1376|ICS Engineering (Construction/Deployment): Security Gaps in Commissioning|category
CWE-1377|ICS Engineering (Construction/Deployment): Inherent Predictability in Design|category
CWE-1378|ICS Operations (& Maintenance): Gaps in obligations and training|category
CWE-1379|ICS Operations (& Maintenance): Human factors in ICS environments|category
CWE-1380|ICS Operations (& Maintenance): Post-analysis changes|category
CWE-1381|ICS Operations (& Maintenance): Exploitable Standard Operational Procedures|category
CWE-1382|ICS Operations (& Maintenance): Emerging Energy Technologies|category
CWE-1383|ICS Operations (& Maintenance): Compliance/Conformance with Regulatory Requirements|category
CWE-1384|Improper Handling of Physical or Environmental Conditions|weakness
CWE-1385|Missing Origin Validation in WebSockets|weakness
CWE-1386|Insecure Operation on Windows Junction / Mount Point|weakness
CWE-1387|Weaknesses in the 2022 CWE Top 25 Most Dangerous Software Weaknesses|view
CWE-1388|Physical Access Issues and Concerns|category
CWE-1389|Incorrect Parsing of Numbers with Different Radices|weakness
CWE-1390|Weak Authentication|weakness
CWE-1391|Use of Weak Credentials|weakness
CWE-1392|Use of Default Credentials|weakness
CWE-1393|Use of Default Password|weakness
CWE-1394|Use of Default Cryptographic Key|weakness
CWE-1395|Dependency on Vulnerable Third-Party Component|weakness
CWE-2000|Comprehensive CWE Dictionary|view
