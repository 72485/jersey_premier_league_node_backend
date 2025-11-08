// models/User.js - User model class for mapping database rows.

/**
 * Represents a User object as stored and processed on the backend server.
 */
class User {
    constructor(row) {
        this.id = row.id;
        this.name = row.name;
        this.email = row.email;
        this.fplTeamID = row.fpl_team_id;
        this.isEmailVerified = row.is_email_verified;
        this.isAdmin = row.is_admin;
        this.verificationToken = row.verification_token;
    }

    /**
     * Converts the User object to a standard JSON response map (excluding sensitive data).
     */
    toJson() {
        return {
            id: this.id,
            name: this.name,
            email: this.email,
            fpl_team_id: this.fplTeamID,
            is_email_verified: this.isEmailVerified,
            is_admin: this.isAdmin,
        };
    }
}

module.exports = User;