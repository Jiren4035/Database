-- AP
College
Academic
Information
System(AIS)
-- Enhanced
Database
Security
Implementation

-- Create
Database
with enhanced security features
CREATE
DATABASE
AIS;
USE
AIS;

-- Enable
SQL
Server
Audit( if available in your
SQL
Server
edition)
-- Note: Some
features
may
require
SQL
Server
Enterprise
Edition

-- == == == == == == == == == == == == == == == == == == == == == =
-- 1.
ENHANCED
SCHEMA
WITH
SECURITY
FEATURES
-- == == == == == == == == == == == == == == == == == == == == == =

-- Original
tables
with security enhancements
CREATE
TABLE
Student(
    ID
VARCHAR(6)
PRIMARY
KEY,
SystemPwd
VARBINARY(256), -- Encrypted
password
storage
PwdSalt
VARBINARY(16), -- Salt
for password hashing
Name VARCHAR(100) NOT NULL,
Phone VARCHAR(20),
CreatedDate DATETIME2 DEFAULT GETDATE(),
ModifiedDate DATETIME2 DEFAULT GETDATE(),
CreatedBy VARCHAR(50) DEFAULT SYSTEM_USER,
ModifiedBy VARCHAR(50) DEFAULT SYSTEM_USER,
IsActive BIT DEFAULT 1,
-- Data classification columns
DataClassification VARCHAR(20) DEFAULT 'Internal' -- Public, Internal, Confidential, Restricted
);

CREATE
TABLE
Lecturer(
    ID
VARCHAR(6)
PRIMARY
KEY,
SystemPwd
VARBINARY(256), -- Encrypted
password
storage
PwdSalt
VARBINARY(16), -- Salt
for password hashing
Name VARCHAR(100) NOT NULL,
Phone VARCHAR(20),
Department VARCHAR(30),
CreatedDate DATETIME2 DEFAULT GETDATE(),
ModifiedDate DATETIME2 DEFAULT GETDATE(),
CreatedBy VARCHAR(50) DEFAULT SYSTEM_USER,
ModifiedBy VARCHAR(50) DEFAULT SYSTEM_USER,
IsActive BIT DEFAULT 1,
-- Data classification columns
DataClassification VARCHAR(20) DEFAULT 'Internal' -- Public, Internal, Confidential, Restricted
);

CREATE
TABLE
Subject(
    Code
VARCHAR(5)
PRIMARY
KEY,
Title
VARCHAR(30),
CreatedDate
DATETIME2
DEFAULT
GETDATE(),
ModifiedDate
DATETIME2
DEFAULT
GETDATE(),
CreatedBy
VARCHAR(50)
DEFAULT
SYSTEM_USER,
ModifiedBy
VARCHAR(50)
DEFAULT
SYSTEM_USER,
DataClassification
VARCHAR(20)
DEFAULT
'Public'
);

CREATE
TABLE
Result(
    ID
INT
PRIMARY
KEY
IDENTITY(1, 1),
StudentID
VARCHAR(6)
REFERENCES
Student(ID),
LecturerID
VARCHAR(6)
REFERENCES
Lecturer(ID),
SubjectCode
VARCHAR(5)
REFERENCES
Subject(Code),
AssessmentDate
DATE,
Grade
VARCHAR(2),
CreatedDate
DATETIME2
DEFAULT
GETDATE(),
ModifiedDate
DATETIME2
DEFAULT
GETDATE(),
CreatedBy
VARCHAR(50)
DEFAULT
SYSTEM_USER,
ModifiedBy
VARCHAR(50)
DEFAULT
SYSTEM_USER,
DataClassification
VARCHAR(20)
DEFAULT
'Confidential' - - Academic
data is confidential
);

-- == == == == == == == == == == == == == == == == == == == == == =
-- 2.
AUDIT
TABLES
-- == == == == == == == == == == == == == == == == == == == == == =

-- System
Login
Audit
Table
CREATE
TABLE
AuditLogin(
    AuditID
INT
PRIMARY
KEY
IDENTITY(1, 1),
UserName
VARCHAR(50),
LoginTime
DATETIME2
DEFAULT
GETDATE(),
LoginStatus
VARCHAR(20), -- Success, Failed
IPAddress
VARCHAR(45),
UserAgent
VARCHAR(500),
FailureReason
VARCHAR(200)
);

-- Database
Activity
Audit
Table
CREATE
TABLE
AuditActivity(
    AuditID
INT
PRIMARY
KEY
IDENTITY(1, 1),
UserName
VARCHAR(50),
ActionType
VARCHAR(50), -- INSERT, UPDATE, DELETE, SELECT
TableName
VARCHAR(50),
RecordID
VARCHAR(50),
OldValues
NVARCHAR(MAX),
NewValues
NVARCHAR(MAX),
ActionTime
DATETIME2
DEFAULT
GETDATE(),
SessionID
VARCHAR(50)
);

-- Data
Classification
Audit
CREATE
TABLE
AuditDataAccess(
    AuditID
INT
PRIMARY
KEY
IDENTITY(1, 1),
UserName
VARCHAR(50),
TableName
VARCHAR(50),
DataClassification
VARCHAR(20),
AccessType
VARCHAR(20), -- READ, WRITE, DELETE
AccessTime
DATETIME2
DEFAULT
GETDATE(),
Authorized
BIT
);

-- == == == == == == == == == == == == == == == == == == == == == =
-- 3.
BACKUP
AND
RECOVERY
TABLES
-- == == == == == == == == == == == == == == == == == == == == == =

-- Soft
Delete
Tables(
for data recovery)
CREATE
TABLE
Student_Deleted(
    ID
VARCHAR(6),
SystemPwd
VARBINARY(256),
PwdSalt
VARBINARY(16),
Name
VARCHAR(100),
Phone
VARCHAR(20),
DeletedDate
DATETIME2
DEFAULT
GETDATE(),
DeletedBy
VARCHAR(50)
DEFAULT
SYSTEM_USER,
OriginalData
NVARCHAR(MAX) - - JSON
representation
of
original
record
);

CREATE
TABLE
Lecturer_Deleted(
    ID
VARCHAR(6),
SystemPwd
VARBINARY(256),
PwdSalt
VARBINARY(16),
Name
VARCHAR(100),
Phone
VARCHAR(20),
Department
VARCHAR(30),
DeletedDate
DATETIME2
DEFAULT
GETDATE(),
DeletedBy
VARCHAR(50)
DEFAULT
SYSTEM_USER,
OriginalData
NVARCHAR(MAX)
);

CREATE
TABLE
Result_Deleted(
    ID
INT,
StudentID
VARCHAR(6),
LecturerID
VARCHAR(6),
SubjectCode
VARCHAR(5),
AssessmentDate
DATE,
Grade
VARCHAR(2),
DeletedDate
DATETIME2
DEFAULT
GETDATE(),
DeletedBy
VARCHAR(50)
DEFAULT
SYSTEM_USER,
OriginalData
NVARCHAR(MAX)
);

-- == == == == == == == == == == == == == == == == == == == == == =
-- 4.
SECURITY
FUNCTIONS
-- == == == == == == == == == == == == == == == == == == == == == =

-- Function
to
generate
salt
CREATE
FUNCTION
GenerateSalt()
RETURNS
VARBINARY(16)
AS
BEGIN
RETURN
CRYPT_GEN_RANDOM(16);
END;

-- Function
to
hash
password
with salt
    CREATE
    FUNCTION
    HashPasswordWithSalt( @ Password
    VARCHAR(100),


    @Salt


    VARBINARY(16))
    RETURNS
    VARBINARY(256)
    AS
    BEGIN
    RETURN
    HASHBYTES('SHA2_256', CAST( @ Password
    AS
    VARBINARY(100)) + @ Salt);
    END;

    -- == == == == == == == == == == == == == == == == == == == == == =
    -- 5.
    AUDIT
    TRIGGERS
    -- == == == == == == == == == == == == == == == == == == == == == =

    -- Student
    Table
    Audit
    Triggers
    CREATE
    TRIGGER
    TR_Student_Audit
    ON
    Student
    AFTER
    INSERT, UPDATE, DELETE
    AS
    BEGIN
    SET
    NOCOUNT
    ON;

    DECLARE @ Action
    VARCHAR(10);
    DECLARE @ UserName
    VARCHAR(50) = SYSTEM_USER;

    IF
    EXISTS(SELECT * FROM
    inserted) AND
    EXISTS(SELECT * FROM
    deleted)
    SET @ Action = 'UPDATE';
    ELSE
    IF
    EXISTS(SELECT * FROM
    inserted)
    SET @ Action = 'INSERT';
    ELSE
    SET @ Action = 'DELETE';

    -- Log
    to
    audit
    table
    INSERT
    INTO
    AuditActivity(UserName, ActionType, TableName, RecordID, OldValues, NewValues)
    SELECT


    @UserName

    ,

    @Action

    ,
    'Student',
    COALESCE(i.ID, d.ID),
    CASE
    WHEN @ Action
    IN('UPDATE', 'DELETE')
    THEN
    (SELECT d.* FOR JSON AUTO)
    END,
    CASE
    WHEN @ Action
    IN('INSERT', 'UPDATE')
    THEN
    (SELECT i.* FOR JSON AUTO)
    END
    FROM
    inserted
    i
    FULL
    OUTER
    JOIN
    deleted
    d
    ON
    i.ID = d.ID;

    -- Handle
    soft
    delete
    for DELETE operations
        IF @ Action = 'DELETE'
    BEGIN
    INSERT
    INTO
    Student_Deleted(ID, SystemPwd, PwdSalt, Name, Phone, OriginalData)
    SELECT
    ID, SystemPwd, PwdSalt, Name, Phone,
    (SELECT d.* FOR JSON AUTO)
    FROM
    deleted
    d;
    END
    END;

    -- Lecturer
    Table
    Audit
    Triggers
    CREATE
    TRIGGER
    TR_Lecturer_Audit
    ON
    Lecturer
    AFTER
    INSERT, UPDATE, DELETE
    AS
    BEGIN
    SET
    NOCOUNT
    ON;

    DECLARE @ Action
    VARCHAR(10);
    DECLARE @ UserName
    VARCHAR(50) = SYSTEM_USER;

    IF
    EXISTS(SELECT * FROM
    inserted) AND
    EXISTS(SELECT * FROM
    deleted)
    SET @ Action = 'UPDATE';
    ELSE
    IF
    EXISTS(SELECT * FROM
    inserted)
    SET @ Action = 'INSERT';
    ELSE
    SET @ Action = 'DELETE';

    INSERT
    INTO
    AuditActivity(UserName, ActionType, TableName, RecordID, OldValues, NewValues)
    SELECT


    @UserName

    ,

    @Action

    ,
    'Lecturer',
    COALESCE(i.ID, d.ID),
    CASE
    WHEN @ Action
    IN('UPDATE', 'DELETE')
    THEN
    (SELECT d.* FOR JSON AUTO)
    END,
    CASE
    WHEN @ Action
    IN('INSERT', 'UPDATE')
    THEN
    (SELECT i.* FOR JSON AUTO)
    END
    FROM
    inserted
    i
    FULL
    OUTER
    JOIN
    deleted
    d
    ON
    i.ID = d.ID;

    IF @ Action = 'DELETE'
    BEGIN
    INSERT
    INTO
    Lecturer_Deleted(ID, SystemPwd, PwdSalt, Name, Phone, Department, OriginalData)
    SELECT
    ID, SystemPwd, PwdSalt, Name, Phone, Department,
    (SELECT d.* FOR JSON AUTO)
    FROM
    deleted
    d;
    END
    END;

    -- Result
    Table
    Audit
    Triggers
    CREATE
    TRIGGER
    TR_Result_Audit
    ON
    Result
    AFTER
    INSERT, UPDATE, DELETE
    AS
    BEGIN
    SET
    NOCOUNT
    ON;

    DECLARE @ Action
    VARCHAR(10);
    DECLARE @ UserName
    VARCHAR(50) = SYSTEM_USER;

    IF
    EXISTS(SELECT * FROM
    inserted) AND
    EXISTS(SELECT * FROM
    deleted)
    SET @ Action = 'UPDATE';
    ELSE
    IF
    EXISTS(SELECT * FROM
    inserted)
    SET @ Action = 'INSERT';
    ELSE
    SET @ Action = 'DELETE';

    INSERT
    INTO
    AuditActivity(UserName, ActionType, TableName, RecordID, OldValues, NewValues)
    SELECT


    @UserName

    ,

    @Action

    ,
    'Result',
    CAST(COALESCE(i.ID, d.ID)
    AS
    VARCHAR(50)),
    CASE
    WHEN @ Action
    IN('UPDATE', 'DELETE')
    THEN
    (SELECT d.* FOR JSON AUTO)
    END,
    CASE
    WHEN @ Action
    IN('INSERT', 'UPDATE')
    THEN
    (SELECT i.* FOR JSON AUTO)
    END
    FROM
    inserted
    i
    FULL
    OUTER
    JOIN
    deleted
    d
    ON
    i.ID = d.ID;

    IF @ Action = 'DELETE'
    BEGIN
    INSERT
    INTO
    Result_Deleted(ID, StudentID, LecturerID, SubjectCode, AssessmentDate, Grade, OriginalData)
    SELECT
    ID, StudentID, LecturerID, SubjectCode, AssessmentDate, Grade,
    (SELECT d.* FOR JSON AUTO)
    FROM
    deleted
    d;
    END
    END;

    -- == == == == == == == == == == == == == == == == == == == == == =
    -- 6.
    SECURITY
    VIEWS
    -- == == == == == == == == == == == == == == == == == == == == == =

    -- Student
    view(hiding
    sensitive
    data)
    CREATE
    VIEW
    vw_Student_Safe
    AS
    SELECT
    ID,
    Name,
    Phone,
    CreatedDate,
    IsActive
    FROM
    Student
    WHERE
    IsActive = 1;

    -- Lecturer
    view(hiding
    sensitive
    data)
    CREATE
    VIEW
    vw_Lecturer_Safe
    AS
    SELECT
    ID,
    Name,
    Phone,
    Department,
    CreatedDate,
    IsActive
    FROM
    Lecturer
    WHERE
    IsActive = 1;

    -- Student
    's own data view
    CREATE
    VIEW
    vw_Student_Own
    AS
    SELECT
    s.ID,
    s.Name,
    s.Phone,
    s.CreatedDate,
    s.IsActive
    FROM
    Student
    s
    WHERE
    s.ID = SYSTEM_USER;
    -- Assumes
    user
    login
    matches
    student
    ID

    -- Student
    's own results view
    CREATE
    VIEW
    vw_Student_Own_Results
    AS
    SELECT
    r.ID,
    r.StudentID,
    r.SubjectCode,
    sub.Title as SubjectTitle,
    r.AssessmentDate,
    r.Grade,
    r.CreatedDate
    FROM
    Result
    r
    INNER
    JOIN
    Subject
    sub
    ON
    r.SubjectCode = sub.Code
    WHERE
    r.StudentID = SYSTEM_USER;
    -- Assumes
    user
    login
    matches
    student
    ID

    -- Lecturer
    's department results view
    CREATE
    VIEW
    vw_Lecturer_Department_Results
    AS
    SELECT
    r.ID,
    r.StudentID,
    s.Name as StudentName,
    r.SubjectCode,
    sub.Title as SubjectTitle,
    r.AssessmentDate,
    r.Grade,
    r.LecturerID,
    r.CreatedDate
    FROM
    Result
    r
    INNER
    JOIN
    Student
    s
    ON
    r.StudentID = s.ID
    INNER
    JOIN
    Subject
    sub
    ON
    r.SubjectCode = sub.Code
    INNER
    JOIN
    Lecturer
    l1
    ON
    r.LecturerID = l1.ID
    INNER
    JOIN
    Lecturer
    l2
    ON
    l1.Department = l2.Department
    WHERE
    l2.ID = SYSTEM_USER;
    -- Results
    from same department

    -- == == == == == == == == == == == == == == == == == == == == == =
    -- 7.
    STORED
    PROCEDURES
    FOR
    SECURE
    OPERATIONS
    -- == == == == == == == == == == == == == == == == == == == == == =

    -- Secure
    login
    procedure
    CREATE
    PROCEDURE
    sp_SecureLogin


    @UserID


    VARCHAR(6),


    @Password


    VARCHAR(100),


    @UserType


    VARCHAR(10) - - 'Student' or 'Lecturer'
    AS
    BEGIN
    SET
    NOCOUNT
    ON;

    DECLARE @ StoredHash
    VARBINARY(256);
    DECLARE @ Salt
    VARBINARY(16);
    DECLARE @ ComputedHash
    VARBINARY(256);
    DECLARE @ LoginStatus
    VARCHAR(20) = 'Failed';
    DECLARE @ FailureReason
    VARCHAR(200) = '';

    BEGIN
    TRY
    IF @ UserType = 'Student'
    BEGIN
    SELECT @ StoredHash = SystemPwd,


    @Salt

    = PwdSalt
    FROM
    Student
    WHERE
    ID =


    @UserID


    AND
    IsActive = 1;
    END
    ELSE
    IF @ UserType = 'Lecturer'
    BEGIN
    SELECT @ StoredHash = SystemPwd,


    @Salt

    = PwdSalt
    FROM
    Lecturer
    WHERE
    ID =


    @UserID


    AND
    IsActive = 1;
    END

    IF @ StoredHash
    IS
    NULL
    BEGIN
    SET @ FailureReason = 'User not found or inactive';
    END
    ELSE
    BEGIN
    SET @ ComputedHash = dbo.HashPasswordWithSalt( @ Password,


    @Salt

    );

    IF @ StoredHash =


    @ComputedHash


    BEGIN
    SET @ LoginStatus = 'Success';
    SET @ FailureReason = '';
    END
    ELSE
    BEGIN
    SET @ FailureReason = 'Invalid password';
    END
    END

    END
    TRY
    BEGIN
    CATCH
    SET @ LoginStatus = 'Error';
    SET @ FailureReason = ERROR_MESSAGE();
    END
    CATCH

    -- Log
    login
    attempt
    INSERT
    INTO
    AuditLogin(UserName, LoginStatus, FailureReason)
    VALUES( @ UserID,


    @LoginStatus

    ,

    @FailureReason

    );

    -- Return
    result
    SELECT @ LoginStatus as LoginStatus,


    @FailureReason

    as Message;
    END;

    -- Secure
    user
    creation
    procedure
    CREATE
    PROCEDURE
    sp_CreateUser


    @UserID


    VARCHAR(6),


    @Password


    VARCHAR(100),


    @Name


    VARCHAR(100),


    @Phone


    VARCHAR(20),


    @UserType


    VARCHAR(10),


    @Department


    VARCHAR(30) = NULL
    AS
    BEGIN
    SET
    NOCOUNT
    ON;

    DECLARE @ Salt
    VARBINARY(16) = dbo.GenerateSalt();
    DECLARE @ HashedPassword
    VARBINARY(256) = dbo.HashPasswordWithSalt( @ Password,


    @Salt

    );

    BEGIN
    TRY
    IF @ UserType = 'Student'
    BEGIN
    INSERT
    INTO
    Student(ID, SystemPwd, PwdSalt, Name, Phone)
    VALUES( @ UserID,


    @HashedPassword

    ,

    @Salt

    ,

    @Name

    ,

    @Phone

    );
    END
    ELSE
    IF @ UserType = 'Lecturer'
    BEGIN
    INSERT
    INTO
    Lecturer(ID, SystemPwd, PwdSalt, Name, Phone, Department)
    VALUES( @ UserID,


    @HashedPassword

    ,

    @Salt

    ,

    @Name

    ,

    @Phone

    ,

    @Department

    );
    END

    SELECT
    'Success' as Status, 'User created successfully' as Message;
    END
    TRY
    BEGIN
    CATCH
    SELECT
    'Error' as Status, ERROR_MESSAGE() as Message;
    END
    CATCH
    END;

    -- == == == == == == == == == == == == == == == == == == == == == =
    -- 8.
    ROLES
    AND
    PERMISSIONS
    -- == == == == == == == == == == == == == == == == == == == == == =

    -- Create
    custom
    database
    roles
    CREATE
    ROLE
    db_student;
    CREATE
    ROLE
    db_lecturer;
    CREATE
    ROLE
    db_admin;

    -- Grant
    permissions
    to
    roles

    -- Student
    role
    permissions
    GRANT
    SELECT
    ON
    vw_Student_Own
    TO
    db_student;
    GRANT
    SELECT
    ON
    vw_Student_Own_Results
    TO
    db_student;
    GRANT
    UPDATE
    ON
    vw_Student_Own
    TO
    db_student;
    DENY
    SELECT
    ON
    Student.SystemPwd
    TO
    db_student;
    DENY
    SELECT
    ON
    Student.PwdSalt
    TO
    db_student;

    -- Lecturer
    role
    permissions
    GRANT
    SELECT
    ON
    vw_Lecturer_Safe
    TO
    db_lecturer;
    GRANT
    SELECT
    ON
    vw_Student_Safe
    TO
    db_lecturer;
    GRANT
    SELECT
    ON
    vw_Lecturer_Department_Results
    TO
    db_lecturer;
    GRANT
    INSERT, UPDATE, DELETE
    ON
    Result
    TO
    db_lecturer;
    GRANT
    SELECT
    ON
    Subject
    TO
    db_lecturer;
    DENY
    SELECT
    ON
    Lecturer.SystemPwd
    TO
    db_lecturer;
    DENY
    SELECT
    ON
    Lecturer.PwdSalt
    TO
    db_lecturer;
    DENY
    SELECT
    ON
    Student.SystemPwd
    TO
    db_lecturer;
    DENY
    SELECT
    ON
    Student.PwdSalt
    TO
    db_lecturer;

    -- Admin
    role
    permissions(full
    access except passwords)
    GRANT
    SELECT, INSERT, UPDATE
    ON
    Student
    TO
    db_admin;
    GRANT
    SELECT, INSERT, UPDATE
    ON
    Lecturer
    TO
    db_admin;
    GRANT
    SELECT, INSERT, UPDATE, DELETE
    ON
    Subject
    TO
    db_admin;
    GRANT
    SELECT
    ON
    Result
    TO
    db_admin;
    GRANT
    SELECT
    ON
    AuditLogin
    TO
    db_admin;
    GRANT
    SELECT
    ON
    AuditActivity
    TO
    db_admin;
    DENY
    SELECT
    ON
    Student.SystemPwd
    TO
    db_admin;
    DENY
    SELECT
    ON
    Student.PwdSalt
    TO
    db_admin;
    DENY
    SELECT
    ON
    Lecturer.SystemPwd
    TO
    db_admin;
    DENY
    SELECT
    ON
    Lecturer.PwdSalt
    TO
    db_admin;

    -- == == == == == == == == == == == == == == == == == == == == == =
    -- 9.
    ROW
    LEVEL
    SECURITY(RLS)
    POLICIES
    - - == == == == == == == == == == == == == == == == == == == == == =

    -- Enable
    RLS
    on
    Student
    table
    ALTER
    TABLE
    Student
    ENABLE
    ROW_LEVEL_SECURITY;

    -- Create
    security
    policy
    for students(own data only)
    CREATE SECURITY POLICY StudentPolicy
    ADD FILTER PREDICATE dbo.fn_StudentAccess(ID) ON Student,
    ADD BLOCK PREDICATE dbo.fn_StudentAccess(ID) ON Student AFTER UPDATE;

    -- Security function for student access
    CREATE FUNCTION fn_StudentAccess( @ StudentID VARCHAR(6))
    RETURNS TABLE
    WITH SCHEMABINDING
    AS
    RETURN (
    SELECT
    1
    AS
    AccessResult
    WHERE
    IS_MEMBER('db_admin') = 1
    OR
    IS_MEMBER('db_lecturer') = 1
    OR
    (@ StudentID = SYSTEM_USER AND IS_MEMBER('db_student') = 1)
    );

    -- == == == == == == == == == == == == == == == == == == == == == =
    -- 10.
    BACKUP
    AUTOMATION
    SCRIPT
    - - == == == == == == == == == == == == == == == == == == == == == =

    -- Create
    procedure
    for automated backup
    CREATE PROCEDURE sp_AutoBackup
    AS
    BEGIN
    DECLARE @ BackupFile VARCHAR(200);
    DECLARE @ DateTime VARCHAR(20) = FORMAT(GETDATE(), 'yyyyMMdd_HHmmss');

    SET @ BackupFile = 'C:\Backups\AIS_' + @ DateTime + '.bak';

    BACKUP DATABASE AIS
    TO DISK = @ BackupFile
    WITH FORMAT, COMPRESSION, CHECKSUM;

    -- Log backup completion
    INSERT INTO AuditActivity (UserName, ActionType, TableName, ActionTime)
    VALUES ('SYSTEM', 'BACKUP', 'DATABASE', GETDATE());
    END;

    -- == == == == == == == == == == == == == == == == == == == == == =
    -- 11. SAMPLE DATA WITH SECURITY
    -- == == == == == == == == == == == == == == == == == == == == == =

    -- Insert sample data using secure procedures
    EXEC sp_CreateUser 'S001', 'Student123!', 'John Smith', '012-3456789', 'Student';
    EXEC sp_CreateUser 'S002', 'Student456!', 'Mary Johnson', '012-9876543', 'Student';
    EXEC sp_CreateUser 'S003', 'Student789!', 'David Brown', '012-5555666', 'Student';

    EXEC sp_CreateUser 'L001', 'Lecturer123!', 'Dr. Sarah Wilson', '03-11111111', 'Lecturer', 'Computer Science';
    EXEC sp_CreateUser 'L002', 'Lecturer456!', 'Prof. Michael Davis', '03-22222222', 'Lecturer', 'Information Technology';

    -- Insert subjects
    INSERT INTO Subject (Code, Title) VALUES
    ('CS101', 'Introduction to Programming'),
    ('CS201', 'Database Systems'),
    ('IT101', 'Network Fundamentals'),
    ('CS301', 'Software Engineering'),
    ('IT201', 'Web Development');

    -- Insert results (using system context)
    INSERT INTO Result (StudentID, LecturerID, SubjectCode, AssessmentDate, Grade) VALUES
    ('S001', 'L001', 'CS101', '2024-06-15', 'A'),
    ('S001', 'L001', 'CS201', '2024-06-20', 'B+'),
    ('S002', 'L002', 'IT101', '2024-06-18', 'A-'),
    ('S002', 'L001', 'CS101', '2024-06-15', 'B'),
    ('S003', 'L002', 'IT201', '2024-06-22', 'A');

    -- == == == == == == == == == == == == == == == == == == == == == =
    -- 12. DAILY AUDIT REPORT PROCEDURES
    -- == == == == == == == == == == == == == == == == == == == == == =

    -- Daily login audit report
    CREATE PROCEDURE sp_DailyLoginAuditReport
    @ ReportDate DATE = NULL
    AS
    BEGIN
    IF @ ReportDate IS NULL
    SET @ ReportDate = CAST(GETDATE() AS DATE);

    SELECT
    CAST(LoginTime AS DATE) as LoginDate,
    UserName,
    LoginStatus,
    COUNT( * ) as AttemptCount,
    MIN(LoginTime) as FirstAttempt,
    MAX(LoginTime) as LastAttempt
    FROM AuditLogin
    WHERE CAST(LoginTime AS DATE) = @ ReportDate
    GROUP BY CAST(LoginTime AS DATE), UserName, LoginStatus
    ORDER BY UserName, LoginStatus;
    END;

    -- Daily activity audit report
    CREATE PROCEDURE sp_DailyActivityAuditReport
    @ ReportDate DATE = NULL
    AS
    BEGIN
    IF @ ReportDate IS NULL
    SET @ ReportDate = CAST(GETDATE() AS DATE);

    SELECT
    CAST(ActionTime AS DATE) as ActivityDate,
    UserName,
    ActionType,
    TableName,
    COUNT( * ) as ActionCount
    FROM AuditActivity
    WHERE CAST(ActionTime AS DATE) = @ ReportDate
    GROUP BY CAST(ActionTime AS DATE), UserName, ActionType, TableName
    ORDER BY UserName, ActionType, TableName;
    END;

    -- == == == == == == == == == == == == == == == == == == == == == =
    -- 13. TEST SCENARIOS
    -- == == == == == == == == == == == == == == == == == == == == == =

    -- Test secure login
    EXEC sp_SecureLogin 'S001', 'Student123!', 'Student';
    EXEC sp_SecureLogin 'S001', 'WrongPassword', 'Student';

    -- Generate daily reports
    EXEC sp_DailyLoginAuditReport;
    EXEC sp_DailyActivityAuditReport;

    -- Test data access (should be run under appropriate user context)
    -- SELECT * FROM vw_Student_Own; -- Student can see own data
    -- SELECT * FROM vw_Student_Own_Results; -- Student can see own results

    -- Test automated backup
    -- EXEC sp_AutoBackup;