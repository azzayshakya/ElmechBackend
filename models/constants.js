// models/constants.js
export const EMPLOYEE_ROLES = ["admin", "ceo", "company_admin", "employee"];

export const PROJECT_STATUSES = [
  "proposed_by_client",             // initial proposal created by client
  "proposal_accepted_by_vendor",    // vendor has accepted the proposal
  "vendor_planning",                // vendor is planning
  "vendor_working",                 // vendor actively working
  "vendor_completed"                // vendor completed the project
];

export const COMPANY_TYPES = ["Client", "Vendor"];
