const transporter = require("../../src/config/Email.config");
const otpGenerator = require("otp-generator");
const jwtResponse = require("../../src/services/JWTresponse").default;
const { TokenGenerate } = require("../utils/jwt");
const verifykey = require("../middleware/auth");
const {
  passwordencrypt,
  validatePassword,
} = require("../services/CommonService");
const responseMessage = require("../utils/ResponseMessage.json");

require("dotenv").config();
const Connection = require("../config/Db.config");

// email password reset forgot update verify
exports.sentotp = async (req, res) => {
  const { email } = req.body;

  try {
    const otp = Math.floor(Math.random().toFixed(4) * 9999);

    const expirationTime = new Date(Date.now() + 3 * 60 * 1000);
    const expirationTimeIST = expirationTime.toLocaleString("en-IN", {
      timeZone: "Asia/Kolkata",
    });

    const updateUserQuery = `UPDATE employee SET otp = ?, otpexpiration = ? WHERE email = ?`;
    Connection.query(
      updateUserQuery,
      [otp, expirationTimeIST, email],
      (err, userResult) => {
        if (err) {
          console.error("Error updating User:", err);
          return res.status(500).json({
            status: 500,
            message: "Internal Server Error",
          });
        }

        const updateStudentQuery = `UPDATE admin SET otp = ?, otpexpiration = ? WHERE email = ?`;
        Connection.query(
          updateStudentQuery,
          [otp, expirationTimeIST, email],
          (err, studentResult) => {
            if (err) {
              console.error("Error updating Student:", err);
              return res.status(500).json({
                status: 500,
                message: "Internal Server Error",
              });
            }

            if (
              userResult.affectedRows === 0 &&
              studentResult.affectedRows === 0
            ) {
              return res.status(404).json({
                status: 404,
                message: "email id is not found",
              });
            } else {
              const mailOptions = {
                from: "parth@example.com",
                to: email,
                subject: "OTP Verification",
                text: `Your OTP for password reset is: ${otp}. Please use this OTP within 10 minutes to reset your password. If you didn't request this, please ignore this email.`,
              };

              transporter.sendMail(mailOptions, (error, info) => {
                if (error) {
                  console.error("Error sending email:", error);
                  return res.status(502).json({
                    status: 502,
                    message: "OTP not sent",
                  });
                } else {
                  console.log("Email sent:", info.response);
                  return res.status(200).json({
                    status: 200,
                    message: "OTP sent Successfully",
                  });
                }
              });
            }
          }
        );
      }
    );
  } catch (error) {
    console.error("Error sending OTP:", error);
    return res.status(500).json({
      status: 500,
      message: "Internal Server Error",
    });
  }
};

// otp verify
exports.verifyOTP = async (req, res) => {
  const { email, otp } = req.body;

  try {
    const selectEmployeeQuery = `SELECT * FROM employee WHERE email = ?`;
    Connection.query(selectEmployeeQuery, [email], (err, employeeResults) => {
      if (err) {
        console.error("Error fetching employee:", err);
        return res.status(500).json({
          status: 500,
          message: "Internal Server Error",
        });
      }

      const employee = employeeResults[0];

      const selectAdminQuery = `SELECT * FROM admin WHERE email = ?`;
      Connection.query(selectAdminQuery, [email], (err, adminResults) => {
        if (err) {
          console.error("Error fetching admin:", err);
          return res.status(500).json({
            status: 500,
            message: "Internal Server Error",
          });
        }

        const admin = adminResults[0];

        if (!employee && !admin) {
          return res.status(404).json({
            status: 404,
            message: "Email not found",
          });
        } else if (employee && otp === employee.otp) {
          const currentTimestampIST = new Date().toLocaleString("en-IN", {
            timeZone: "Asia/Kolkata",
          });

          if (employee.otpexpiration < currentTimestampIST) {
            return res.status(400).json({
              status: 400,
              message: "OTP has expired",
            });
          } else {
            const updateEmployeeQuery = `UPDATE employee SET otp = null WHERE email = ?`;
            Connection.query(
              updateEmployeeQuery,
              [email],
              (err, updateResult) => {
                if (err) {
                  console.error("Error updating employee:", err);
                  return res.status(500).json({
                    status: 500,
                    message: "Internal Server Error",
                  });
                }

                return res.status(201).json({
                  status: 201,
                  message: "OTP verified successfully for employee",
                });
              }
            );
          }
        } else if (admin && otp === admin.otp) {
          const currentTimestampIST = new Date().toLocaleString("en-IN", {
            timeZone: "Asia/Kolkata",
          });

          if (admin.otpexpiration < currentTimestampIST) {
            return res.status(400).json({
              status: 400,
              message: "OTP has expired",
            });
          } else {
            const updateAdminQuery = `UPDATE admin SET otp = null WHERE email = ?`;
            Connection.query(updateAdminQuery, [email], (err, updateResult) => {
              if (err) {
                console.error("Error updating admin:", err);
                return res.status(500).json({
                  status: 500,
                  message: "Internal Server Error",
                });
              }

              return res.status(201).json({
                status: 201,
                message: "OTP verified successfully for admin",
              });
            });
          }
        } else {
          return res.status(400).json({
            status: 400,
            message: "Invalid OTP, please enter a valid OTP",
          });
        }
      });
    });
  } catch (error) {
    console.error("Error verifying OTP:", error);
    return res.status(500).json({
      status: 500,
      message: "Error while verifying OTP",
    });
  }
};

// verify opt n reset pass
exports.resetPassword = async (req, res) => {
  const { email, password, confirmPassword } = req.body;

  if (!password || !confirmPassword || !email) {
    return res.status(403).json({
      status: 403,
      error: true,
      message: "All Fields Are Required",
    });
  } else if (!validatePassword(password)) {
    return res.status(400).json({
      status: 400,
      message: "EWnter Valied Password Formate",
    });
  } else {
    try {
      const selectEmployeeQuery = `SELECT * FROM employee WHERE email = ?`;
      Connection.query(
        selectEmployeeQuery,
        [email],
        async (err, employeeResults) => {
          if (err) {
            console.error("Error fetching employee:", err);
            return res.status(500).json({
              status: 500,
              message: "Internal Server Error",
            });
          }

          const employee = employeeResults[0];

          const selectAdminQuery = `SELECT * FROM admin WHERE email = ?`;
          Connection.query(
            selectAdminQuery,
            [email],
            async (err, adminResults) => {
              if (err) {
                console.error("Error fetching admin:", err);
                return res.status(500).json({
                  status: 500,
                  message: "Internal Server Error",
                });
              }

              const admin = adminResults[0];

              if (!employee && !admin) {
                return res.status(404).json({
                  status: 404,
                  message: "Email id not found",
                });
              } else if (password !== confirmPassword) {
                return res.status(400).json({
                  status: 400,
                  message: "Password and Confirm Password do not match",
                });
              } else {
                const currentTimestampIST = new Date().toLocaleString("en-IN", {
                  timeZone: "Asia/Kolkata",
                });

                if (employee && employee.otpexpiration < currentTimestampIST) {
                  return res.status(400).json({
                    status: 400,
                    message:
                      "Request timeout for employee, please request a new OTP",
                  });
                } else if (admin && admin.otpexpiration < currentTimestampIST) {
                  return res.status(400).json({
                    status: 400,
                    message:
                      "Request timeout for admin, please request a new OTP",
                  });
                } else {
                  const hashedPassword = await passwordencrypt(password);

                  if (employee) {
                    const updatePasswordQuery = `UPDATE employee SET otpexpiration = NULL , password = ?  WHERE email = ?`;
                    Connection.query(
                      updatePasswordQuery,
                      [hashedPassword, email],
                      (err, updateResult) => {
                        if (err) {
                          console.error(
                            "Error updating employee password:",
                            err
                          );
                          return res.status(500).json({
                            status: 500,
                            message: "Internal Server Error",
                          });
                        }

                        return res.status(201).json({
                          status: 201,
                          message: "Password reset successfully for employee",
                        });
                      }
                    );
                  } else if (admin) {
                    const updatePasswordQuery = `UPDATE admin SET otpexpiration = NULL ,  password = ? WHERE email = ?`;
                    Connection.query(
                      updatePasswordQuery,
                      [hashedPassword, email],
                      (err, updateResult) => {
                        if (err) {
                          console.error("Error updating admin password:", err);
                          return res.status(500).json({
                            status: 500,
                            message: "Internal Server Error",
                          });
                        }

                        return res.status(201).json({
                          status: 201,
                          message: "Password reset successfully for admin",
                        });
                      }
                    );
                  }
                }
              }
            }
          );
        }
      );
    } catch (error) {
      console.error("Error resetting password:", error);
      return res.status(500).json({
        status: 500,
        message: "Error while resetting password",
      });
    }
  }
};
