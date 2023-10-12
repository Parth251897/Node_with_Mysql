const bcrypt = require("bcrypt");
const mysql = require("mysql");
const jwt = require("jsonwebtoken");
require("dotenv").config();
const { StatusCodes } = require("http-status-codes");
const responsemessage = require("../../utils/ResponseMessage.json");
const {
  passwordencrypt,
  validatePassword,
} = require("../../services/CommonService");
const { generateJwt } = require("../../utils/jwt");
const connection = require("../../config/Db.config");
const { blockTokens } = require("../../middleware/auth");

exports.SignUp = async (req, res) => {
  try {
    let { EmpName, email, phone, password } = req.body;

    // Generate a unique username
    const randomFourDigits = Math.floor(Math.random() * 10000);
    const userName =
      EmpName.replace(/\s/g, "").toLowerCase() +
      String(randomFourDigits).padStart(4, "0");

    phone = parseInt(phone, 10);

    // Check if email or phone number already exist
    const checkQuery = "SELECT * FROM employee WHERE email = ? OR phone = ?";
    connection.query(checkQuery, [email, phone], async (error, results) => {
      if (error) {
        return res.status(500).json({
          status: StatusCodes.INTERNAL_SERVER_ERROR,
          message: responsemessage.INTERNAL_SERVER_ERROR,
        });
      }

      const existEmail = results.find((employee) => employee.email === email);
      const existPhone = results.find((employee) => employee.phone === phone);

      if (existEmail || existPhone) {
        const message = existEmail
          ? responsemessage.EMAILEXISTS
          : responsemessage.PHONEEXISTS;
        return res.status(400).json({
          status: StatusCodes.BAD_REQUEST,
          message,
        });
      } else {
        if (!validatePassword(password)) {
          return res.status(400).json({
            status: StatusCodes.BAD_REQUEST,
            message: responsemessage.VALIDATEPASS,
          });
        } else {
          const hashPassword = await passwordencrypt(password);
          const insertQuery =
            "INSERT INTO employee (userName, EmpName, email, phone, password) VALUES (?, ?, ?, ?, ?)";
          connection.query(
            insertQuery,
            [userName, EmpName, email, phone, hashPassword],
            (error, insertResults) => {
              if (error) {
                return res.status(400).json({
                  status: StatusCodes.BAD_REQUEST,
                  message: responsemessage.NOTCREATED,
                });
              } else {
                return res.status(201).json({
                  status: StatusCodes.CREATED,
                  message: responsemessage.CREATED,
                  insertResults,
                });
              }
            }
          );
        }
      }
    });
  } catch (error) {
    return res.status(500).json({
      status: StatusCodes.INTERNAL_SERVER_ERROR,
      message: responsemessage.INTERNAL_SERVER_ERROR,
    });
  }
};

exports.SignIn = async (req, res) => {
  try {
    const { masterfield, userName, email, phone, password } = req.body;

    const selectdata =
      "SELECT * FROM employee WHERE email = ? OR userName = ? OR phone = ?";
    connection.query(
      selectdata,
      [masterfield, masterfield, masterfield],
      async (err, results) => {
        // if (err) {
        //   return res.status(400).json({
        //     status: StatusCodes.BAD_REQUEST,
        //     message: responsemessage.NOTFOUND,
        //   });
        // } else
        if (!results || results.length === 0) {
          return res.status(404).json({
            status: StatusCodes.BAD_REQUEST,
            error: true,
            message: responsemessage.NOTFOUND,
          });
        } else {
          const userLogin = results[0];

          if (userLogin.isActive) {
            return res.status(401).json({
              status: StatusCodes.UNAUTHORIZED,
              message: responsemessage.UNAUTHORIZED,
            });
          } else {
            const isvalid = await bcrypt.compare(password, userLogin.password);

            if (!isvalid) {
              return res.status(400).json({
                status: StatusCodes.BAD_REQUEST,
                error: true,
                message: responsemessage.NOTMATCH,
              });
            } else {
              const { error, token } = await generateJwt(userLogin.id);
              if (error) {
                return res.status(400).json({
                  status: StatusCodes.BAD_REQUEST,
                  error: true,
                  message: responsemessage.TOKEN,
                });
              } else {
                return res.status(200).json({
                  status: StatusCodes.OK,
                  userLogin: userLogin.email,
                  phone: userLogin.phone,
                  success: true,
                  token: token,
                  message: responsemessage.SUCCESS,
                });
              }
            }
          }
        }
      }
    );
  } catch (error) {
    return res.status(500).json({
      status: StatusCodes.INTERNAL_SERVER_ERROR,
      message: responsemessage.INTERNAL_SERVER_ERROR,
    });
  }
};

exports.UserFind = async (req, res) => {
  try {
    const token = req.headers.authorization;

    if (blockTokens.has(token)) {
      return res.status(401).json({
        status: StatusCodes.UNAUTHORIZED,
        message: "User logged out.",
      });
    } else {
      let userId = req.currentUser;

      const selectdata = "SELECT * FROM employee WHERE id = ?";
      connection.query(selectdata, [userId], async (error, results) => {
        if (error) {
          return res.status(400).json({
            status: StatusCodes.BAD_REQUEST,
            message: responsemessage.NOTFOUND,
          });
        } else {
          res.status(200).json({
            status: StatusCodes.OK,
            results,
            message: responsemessage.FOUNDUSER,
          });
        }
      });
    }
  } catch (error) {
    return res.status(500).json({
      status: StatusCodes.INTERNAL_SERVER_ERROR,
      message: responsemessage.INTERNAL_SERVER_ERROR,
    });
  }
};

//soft delete
exports.UserDelete = async (req, res) => {
  try {
    let userId = req.currentUser;

    const selectdata = "SELECT * FROM employee WHERE id = ?";
    connection.query(selectdata, [userId], async (error, results) => {
      if (error) {
        return res.status(404).json({
          status: StatusCodes.NOT_FOUND,
          message: responsemessage.NOTFOUND,
        });
      } else {
        const user = results[0];

        const updatedata = "UPDATE employee SET isActive = true WHERE id = ?";
        connection.query(updatedata, [userId], (error) => {
          if (error) {
            return res.status(404).json({
              status: StatusCodes.NOT_FOUND,
              message: responsemessage.NOTFOUND,
            });
          } else {
            return res.status(200).json({
              status: StatusCodes.OK,
              user,
              message: responsemessage.DELETE,
            });
          }
        });
      }
    });
  } catch (error) {
    return res.status(500).json({
      status: StatusCodes.INTERNAL_SERVER_ERROR,
      message: responsemessage.INTERNAL_SERVER_ERROR,
    });
  }
};

//Hard delete
exports.UserDeleteAccount = async (req, res) => {
  try {
    let userId = req.currentUser;

    const selectdata = "SELECT * FROM employee WHERE id = ?";
    connection.query(selectdata, [userId], async (error, results) => {
      if (error) {
        return res.status(404).json({
          status: StatusCodes.NOT_FOUND,
          message: responsemessage.NOTFOUND,
        });
      }
      if (results.length === 0) {
        return res.status(404).json({
          status: StatusCodes.NOT_FOUND,
          message: responsemessage.NOTFOUND,
        });
      }

      const user = results[0];

      const deletedata = "DELETE FROM employee WHERE id = ?";
      connection.query(deletedata, [userId], (error) => {
        if (error) {
          return res.status(404).json({
            status: StatusCodes.NOT_FOUND,
            message: responsemessage.NOTFOUND,
          });
        } else {
          return res.status(200).json({
            status: StatusCodes.OK,
            user,
            message: responsemessage.DELETED,
          });
        }
      });
    });
  } catch (error) {
    return res.status(500).json({
      status: StatusCodes.INTERNAL_SERVER_ERROR,
      message: responsemessage.INTERNAL_SERVER_ERROR,
    });
  }
};

//change password
exports.ChangePassword = async (req, res) => {
  try {

    const {  oldPassword, newPassword, confirmPassword } = req.body;
let userId = req.currentUser;
    const selectQuery = "SELECT * FROM employee WHERE id = ?";

    connection.query(selectQuery, [userId], async (error, results) => {
      if (results.length === 0) {
        return res.status(404).json({
          status: StatusCodes.NOT_FOUND,
          message: responsemessage.NOTFOUND,
        });
      } else {
        const user = results[0];
        console.log(user);

        if (!validatePassword(newPassword)) {
          return res.status(400).json({
            status: StatusCodes.BAD_REQUEST,
            message: responsemessage.VALIDATEPASS,
          });
        } else {
          const isMatch = await bcrypt.compare(oldPassword, user.password);

          if (!isMatch) {
            return res.status(400).json({
              status: StatusCodes.BAD_REQUEST,
              message: responsemessage.OLDPASSWORD,
            });
          } else {
            const isSamePassword = await bcrypt.compare(
              newPassword,
              user.password
            );
            if (isSamePassword) {
              return res.status(400).json({
                status: StatusCodes.BAD_REQUEST,
                message: responsemessage.NEWDIFFERENTOLD,
              });
            } else if (newPassword !== confirmPassword) {
              return res.status(400).json({
                status: StatusCodes.BAD_REQUEST,
                message: responsemessage.NEWCOMMATCH,
              });
            } else {
              const hashedPassword = await passwordencrypt(newPassword);
              const updateQuery =
                "UPDATE employee SET password = ? WHERE id = ?";
              connection.query(
                updateQuery,
                [hashedPassword, userId],
                (updateError) => {
                  if (updateError) {
                    console.log(updateError);
                    return res.status(400).json({
                      status: StatusCodes.BAD_REQUEST,
                      message: responsemessage.PASSNOTCHANGE,
                    });
                  } else {
                    return res.status(200).json({
                      status: 200,
                      message: responsemessage.PSSWORDCHANGESUCC,
                    });
                  }
                }
              );
            }
          }
        }
      }
    });
  } catch (error) {
    return res.status(500).json({
      status: 500,
      message: "Internal server error",
    });
  }
};

exports.UserUpdate = async (req, res) => {
  try {
    let { email, phone } = req.body;
  
    let userId = req.currentUser;

    const selectQuery = "SELECT * FROM employee WHERE id = ?";

    connection.query(selectQuery, [userId], async (error, results) => {
      if (error) {
        return res.status(404).json({
          status: StatusCodes.NOT_FOUND,
          message: responsemessage.NOTFOUND,
        });
      } else {
        const existingUser = results[0];
        const checkQuery =
          "SELECT * FROM employee WHERE email = ? OR phone = ?";

        connection.query(checkQuery, [email, phone], async (error, results) => {
          let existemail = results.find((employee) => employee.email === email);

          const existphone = results.find(
            (employee) => employee.phone === parseInt(phone, 10)
          );

          if (existemail || existphone) {
            const message = existemail
              ? responsemessage.EMAILEXITS
              : responsemessage.phoneEXITS;

            res.status(400).json({
              status: StatusCodes.BAD_REQUEST,
              message,
            });
          } else {
            // const useremail = email ? email.toLowerCase() : undefined;
            console.log();
            // const profile = req.profileUrl;
            // const document = JSON.stringify(req.documentUrl);

            const updatedatas = [];
            const updateValues = [];

            if (email) {
              updatedatas.push("email = ?");
              updateValues.push(email.toLowerCase());
            }
            if (phone) {
              updatedatas.push("phone = ?");
              updateValues.push(phone);
            }
            // if (profile) {
            //   updatedatas.push("profile = ?");
            //   updateValues.push(profile);
            // }
            // if (document) {
            //   updatedatas.push("document = ?");
            //   updateValues.push(document);
            // }
            if (updatedatas.length === 0) {
              return res.status(404).json({
                status: StatusCodes.NOT_FOUND,
                message: responsemessage.NOTFOUND,
              });
            } else {
              const updateQuery = `UPDATE employee SET ${updatedatas.join(
                ", "
              )} WHERE id = ?`;
              updateValues.push(userId);

              connection.query(updateQuery, updateValues, (error) => {
                if (error) {
                  return res.status(400).json({
                    status: StatusCodes.BAD_REQUEST,
                    message: responsemessage.NOTUPDATE,
                  });
                }

                res.status(200).json({
                  status: StatusCodes.OK,
                  message: responsemessage.UPDATE,
                });
              });
            }
          }
        });
      }
    });
  } catch (error) {
    return res.status(500).json({
      status: StatusCodes.INTERNAL_SERVER_ERROR,
      message: responsemessage.INTERNAL_SERVER_ERROR,
    });
  }
};


exports.UserLogout = async (req, res) => {
  const token = req.headers.authorization;

  blockTokens.add(token);

  return res.status(200).json({
    status: StatusCodes.OK,
    message: responsemessage.USERLOGOUT,
  });
};




exports.SendOTP = async (req, res) => {
  try {
    const { email } = req.body;

    const expiry = Date.now() + 2 * 60 * 1000; // 10 minutes
    const expiryIST = new Date(expiry).toLocaleString("en-IN", {
      timeZone: "Asia/Kolkata",
    });

    const userQuery = "SELECT * FROM employee WHERE email = ?";

    connection.query(userQuery, [email], async (userError, userRows) => {
      // console.log(userRows);
      // if (userError) {
      //   console.log("Error selecting user:", userError);
      //   return res.status(500).json({
      //     status: 500,
      //     message: responsemessage.INTERROR,
      //   });
      // }

      if (userRows.length === 0) {
        return res.status(404).json({
          status: StatusCodes.NOT_FOUNDSta,
          message: responsemessage.NOTFOUND,
        });
      } else {
        const OTP = generateOTP(); // Replace this with your OTP generation logic

        const updateUserQuery =
          "UPDATE employee SET otp = ?, otpExpire = ? WHERE email = ?";

        const updateParams = [OTP, expiryIST, email];

        connection.query(
          updateUserQuery,
          updateParams,
          async (updateUserError, updateResult) => {
            let response = await sendEmail(email, OTP);
            if (response.error) {
              return res.status(503).json({
                status: StatusCodes.SERVICE_UNAVAILABLE,
                message: responsemessage.SERVICE_UNAVAILABLE,
              });
            } else {
              console.log("Email sent:", response.email);
              return res.status(200).json({
                status: StatusCodes.OK,
                email: email,
                OTP: OTP,
                otpExpire: expiryIST,
                message: responsemessage.FOUNDDETAILS,
              });
            }
          }
        );
      }
    });
  } catch (error) {
    // console.error("OTP error:", error);
    return res.status(500).json({
      status: StatusCodes.INTERNAL_SERVER_ERROR,
      message: responsemessage.INTERNAL_SERVER_ERROR,
    });
  }
};

exports.ForgotPassword = async (req, res) => {
  try {
    const { email, newPassword, confirmPassword } = req.body;
    if (!newPassword || !confirmPassword || !email) {
      return res.status(400).json({
        status: 400,
        error: true,
        message: responsemessage.NOTEMPTY,
      });
    } else if (!validatePassword(newPassword)) {
      return res.status(400).json({
        status: StatusCodes.BAD_REQUEST,
        message: responsemessage.VALIDATEPASS,
      });
    } else {
      let selectQuery = "SELECT * FROM employee WHERE email = ?";
      connection.query(selectQuery, [email], async (userError, userRows) => {
        if (userRows.length === 0) {
          return res.status(404).json({
            status: StatusCodes.NOT_FOUND,
            message: responsemessage.NOTFOUND,
          });
        } else {
          const user = userRows[0];

          if (newPassword !== confirmPassword) {
            return res.status(400).json({
              status: StatusCodes.BAD_REQUEST,
              message: responsemessage.NOTMATCH,
            });
          } else if (
            user.otpExpire <
            new Date().toLocaleString("en-IN", {
              timeZone: "Asia/Kolkata",
            })
          ) {
            return res.status(400).json({
              status: StatusCodes.BAD_REQUEST,
              message: responsemessage.TIMEOUT,
            });
          } else {
            const passwordHash = await passwordencrypt(newPassword);

            connection.query(
              "UPDATE employee SET  otp = NULL,otpExpire= NULL,password = ? WHERE email = ?",
              [passwordHash, email],
              (updateError) => {
                if (updateError) {
                  console.log(updateError);
                  return res.status(400).json({
                    status: StatusCodes.BAD_REQUEST,
                    message: responsemessage.PASSNOTCHANGE,
                  });
                } else {
                  return res.status(200).json({
                    status: StatusCodes.OK,
                    message: responsemessage.PASSWORDCHANGE,
                  });
                }
              }
            );
          }
        }
      });
    }
  } catch (error) {
    // console.error("reset-password-error", error);
    return res.status(500).json({
      status: StatusCodes.INTERNAL_SERVER_ERROR,
      message: responsemessage.INTERNAL_SERVER_ERROR,
    });
  }
};
